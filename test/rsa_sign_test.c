// RSA-PSS signing: the known answers in test/rsa_sign_vectors.h, a round
// trip through rsa_pss_verify, and the inputs rsa_pss_sign refuses. Its
// own binary with a private main, like the other standalone test mains.
//
// The salt makes a signature: one message signed twice under two salts
// gives two signatures, and neither is wrong. So the known answers pin
// the salt. rsa_pss_sign takes the salt as an argument, which is what
// makes an exact comparison possible; test/gen_rsa_sign_vectors.py says
// how the expected signatures were produced and how openssl checked them.
//
// This binary builds with -DCH_RSA_MODULUS_MAX=512, the TRUST=webpki
// bound bin/rsa_test uses, so the RSA-4096 vector signs here. A device
// build stops at RSA-3072 and refuses that key on its length.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "rsa.h"
#include "rsa_sign.h"
#include "rsa_sign_key.h"
#include "sha256.h"
#include "test_widemul.h"

// The two bounds rsa.h defines. This binary builds at 512 and signs
// every vector; a build at the device bound of 384 runs the refusal
// arm in run_vector for the RSA-4096 key, which is the only arm that
// bound can run, and the lint pass that compiles this file without the
// define reads the same code.
_Static_assert(CH_RSA_MODULUS_MAX == 384 || CH_RSA_MODULUS_MAX == 512,
               "rsa_sign_test knows the device bound and the webpki bound");

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// One vector: a key, the message it signs, the salt, and the signature
// that pair must produce.
typedef struct {
    const char *name;
    test_rsa_sign_key key;
    const uint8_t *n;
    size_t n_len;
    const uint8_t *msg;
    size_t msg_len;
    const uint8_t *salt;
    const uint8_t *sig;
} vector;

#define VECTOR(bits)                                                                               \
    {"RSA-" #bits,           TEST_RSA_SIGN_KEY(bits),                                              \
     rsa_sign_##bits##_n,    sizeof rsa_sign_##bits##_n,                                           \
     rsa_sign_##bits##_msg,  sizeof rsa_sign_##bits##_msg,                                         \
     rsa_sign_##bits##_salt, rsa_sign_##bits##_sig}

static ch_rsa_priv g_key;

static void load_key(const vector *v) {
    test_rsa_sign_key_load(&g_key, &v->key);
}

// The key test of the signer this binary names (test/test_widemul.h).
static int key_ok(void) {
    return widemul_rsa_pss_sign_key_ok(TEST_WIDEMUL, &g_key);
}

// rsa_pss_sign with g_key, under the answer this binary names
// (test/test_widemul.h).
static int sign(const uint8_t msg_hash[SHA256_LEN], const uint8_t *salt, uint8_t *sig, size_t cap,
                size_t *sig_len) {
    return widemul_rsa_pss_sign(TEST_WIDEMUL, &g_key, msg_hash, salt, sig, cap, sig_len);
}

// The known answer, then the round trip: the tree's own verifier accepts
// what the signer produced, and a second salt gives a different signature
// that verifies too.
static void run_vector(const vector *v) {
    uint8_t msg_hash[SHA256_LEN];
    sha256 h;
    sha256_init(&h);
    sha256_update(&h, v->msg, v->msg_len);
    sha256_final(&h, msg_hash);

    if (v->n_len > CH_RSA_MODULUS_MAX) {
        // This build's bound is below the vector's modulus, so the key
        // does not fit ch_rsa_priv at all. rsa_pss_sign must refuse the
        // length before it reads a byte of the key, which is what this
        // arm checks, with the key left zero.
        uint8_t small[CH_RSA_MODULUS_MAX];
        size_t small_len = 0;
        memset(&g_key, 0, sizeof g_key);
        g_key.n_len = v->n_len;
        CHECK(sign(msg_hash, v->salt, small, sizeof small, &small_len) == 0);
        (void)fprintf(stderr, "ok %s refused at this build's modulus bound\n", v->name);
        return;
    }

    load_key(v);
    uint8_t sig[CH_RSA_MODULUS_MAX];
    size_t sig_len = 0;
    CHECK(sign(msg_hash, v->salt, sig, sizeof sig, &sig_len) == 1);
    CHECK(sig_len == v->n_len);
    CHECK(memcmp(sig, v->sig, v->n_len) == 0);
    CHECK(rsa_pss_verify(v->n, v->n_len, msg_hash, sig, sig_len) == 1);

    uint8_t other_salt[RSA_PSS_SALT_LEN];
    memset(other_salt, 0x11, sizeof other_salt);
    uint8_t sig2[CH_RSA_MODULUS_MAX];
    size_t sig2_len = 0;
    CHECK(sign(msg_hash, other_salt, sig2, sizeof sig2, &sig2_len) == 1);
    CHECK(memcmp(sig2, sig, v->n_len) != 0);
    CHECK(rsa_pss_verify(v->n, v->n_len, msg_hash, sig2, sig2_len) == 1);

    // A signature over one message does not verify against another
    // digest, which is the property the whole scheme exists for.
    uint8_t other_hash[SHA256_LEN];
    memcpy(other_hash, msg_hash, sizeof other_hash);
    other_hash[0] ^= 0x01;
    CHECK(rsa_pss_verify(v->n, v->n_len, other_hash, sig, sig_len) == 0);
    (void)fprintf(stderr, "ok %s\n", v->name);
}

// Every input rsa_pss_sign refuses, each one value away from an input it
// accepts where that is possible: the length bounds and the two shapes a
// modulus must have. rsa_pss_sign_key_ok, the test a server runs on its
// configuration, gives the signer's answer at each key.
static void run_refusals(const vector *v) {
    uint8_t sig[CH_RSA_MODULUS_MAX];
    size_t sig_len = 0;
    const uint8_t *salt = v->salt;
    uint8_t msg_hash[SHA256_LEN];
    memset(msg_hash, 0x42, sizeof msg_hash);

    load_key(v);
    CHECK(key_ok() == 1);
    CHECK(sign(msg_hash, salt, sig, v->n_len - 1, &sig_len) == 0); // cap one short
    CHECK(sign(msg_hash, salt, sig, v->n_len, &sig_len) == 1);     // cap exact

    load_key(v);
    g_key.n_len = 248; // one 8-byte step below the RSA-2048 floor
    CHECK(sign(msg_hash, salt, sig, sizeof sig, &sig_len) == 0);
    CHECK(key_ok() == 0);
    g_key.n_len = 260; // inside the bounds, not a multiple of 8
    CHECK(sign(msg_hash, salt, sig, sizeof sig, &sig_len) == 0);
    CHECK(key_ok() == 0);
    g_key.n_len = CH_RSA_MODULUS_MAX + 8; // one step above the ceiling
    CHECK(sign(msg_hash, salt, sig, sizeof sig, &sig_len) == 0);
    CHECK(key_ok() == 0);

    load_key(v);
    g_key.n[g_key.n_len - 1] &= (uint8_t)~1U; // even modulus, no Montgomery inverse
    CHECK(sign(msg_hash, salt, sig, sizeof sig, &sig_len) == 0);
    CHECK(key_ok() == 0);

    load_key(v);
    g_key.n[0] &= 0x7f; // top bit clear, so emLen would not be n_len
    CHECK(sign(msg_hash, salt, sig, sizeof sig, &sig_len) == 0);
    CHECK(key_ok() == 0);
}

#ifdef CH_CPU_RUNTIME
// One call with a key whose CRT integer at byte was changed by one bit.
// It reports whether the call signed, and requires that a call that did
// not sign wrote no byte of sig and left sig_len alone.
static int signs_with_bit_flipped(const vector *v, uint8_t *byte, const uint8_t *msg_hash) {
    uint8_t sig[CH_RSA_MODULUS_MAX];
    uint8_t untouched[CH_RSA_MODULUS_MAX];
    size_t sig_len = 12345;
    memset(sig, 0xa5, sizeof sig);
    memset(untouched, 0xa5, sizeof untouched);
    *byte ^= 0x04;
    int signed_ok = sign(msg_hash, v->salt, sig, sizeof sig, &sig_len);
    *byte ^= 0x04;
    if (!signed_ok) {
        CHECK(memcmp(sig, untouched, sizeof sig) == 0);
        CHECK(sig_len == 12345);
    }
    return signed_ok;
}

// A fault in one half of the CRT, modeled as one bit of one of the five
// integers changed: each makes that half, or the recombination, compute
// another value than the key's, as a fault in the arithmetic would. A
// signature computed that way and returned would factor the modulus, so
// the 64-bit signer must return an error and no signature bytes. The
// ladder reads none of the five, so under its answer every call signs.
static void run_faults(const vector *v) {
    uint8_t msg_hash[SHA256_LEN];
    memset(msg_hash, 0x37, sizeof msg_hash);
    int crt_runs = TEST_WIDEMUL == WIDEMUL_CONSTANT_TIME;
    size_t half_len = v->n_len / 2;
    load_key(v);
    uint8_t *integers[] = {g_key.p, g_key.q, g_key.dp, g_key.dq, g_key.qinv};
    static const char *const names[] = {"p", "q", "dp", "dq", "qinv"};
    for (size_t i = 0; i < sizeof integers / sizeof integers[0]; i++) {
        // The first byte, the last, and one in the middle.
        size_t at[] = {0, half_len / 2, half_len - 1};
        for (size_t j = 0; j < sizeof at / sizeof at[0]; j++) {
            int signed_ok = signs_with_bit_flipped(v, &integers[i][at[j]], msg_hash);
            if (signed_ok == crt_runs) {
                failures++;
                (void)fprintf(stderr, "FAIL %s: a bit of %s changed at byte %zu, and the %s\n",
                              v->name, names[i], at[j],
                              crt_runs ? "64-bit signer returned a signature"
                                       : "ladder, which reads none of the five, refused");
            }
        }
    }
    // The primes are held to the modulus by the key test, before a
    // signature starts; the other three only by the signature's check.
    if (crt_runs) {
        g_key.p[half_len - 1] ^= 0x04;
        CHECK(key_ok() == 0);
        g_key.p[half_len - 1] ^= 0x04;
        g_key.dp[half_len - 1] ^= 0x04;
        CHECK(key_ok() == 1);
        g_key.dp[half_len - 1] ^= 0x04;
    }
    // The key as it was signs again.
    uint8_t sig[CH_RSA_MODULUS_MAX];
    size_t sig_len = 0;
    CHECK(sign(msg_hash, v->salt, sig, sizeof sig, &sig_len) == 1);
    (void)fprintf(stderr, "ok %s faults\n", v->name);
}
#endif

// A host binary takes the ch_cfg.cpu value it runs under as its one
// argument (test/test_cpu.h); every other binary takes none.
int main(int argc, char **argv) {
    test_take_cpu(argc, argv);
    const vector vectors[] = {VECTOR(2048), VECTOR(2112), VECTOR(3072), VECTOR(4096)};
    for (size_t i = 0; i < sizeof vectors / sizeof vectors[0]; i++) {
        run_vector(&vectors[i]);
    }
    run_refusals(&vectors[0]);
#ifdef CH_CPU_RUNTIME
    // RSA-2048, and RSA-2112, whose primes are half a word past a whole
    // number of 64-bit words.
    run_faults(&vectors[0]);
    run_faults(&vectors[1]);
#endif

    if (failures != 0) {
        (void)fprintf(stderr, "rsa_sign_test: %d failure(s)\n", failures);
        return 1;
    }
    (void)printf("rsa_sign_test: all checks passed\n");
    return 0;
}
