// RSA-PSS signing: the known answers in test/rsa_sign_vectors.h, a round
// trip through rsa_pss_verify, and the inputs rsa_pss_sign refuses. Its
// own binary with a private main, like the other standalone test mains.
//
// The salt makes a signature: one message signed twice under two salts
// gives two signatures, and neither is wrong. So the known answers pin
// the salt. ch_rand_bytes below hands out whatever the test loaded
// before the call, which is what makes an exact comparison possible;
// test/gen_rsa_sign_vectors.py says how the expected signatures were
// produced and how openssl checked them.
//
// This binary builds with -DCH_RSA_MODULUS_MAX=512, the TRUST=webpki
// bound bin/rsa_test uses, so the RSA-4096 vector signs here. A device
// build stops at RSA-3072 and refuses that key on its length.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "rand.h"
#include "rsa.h"
#include "rsa_sign.h"
#include "rsa_sign_vectors.h"
#include "sha256.h"

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

// The salt the next signature draws. load_salt puts one there; the hook
// repeats its last byte if a caller ever asks for more than 32, which no
// caller here does. rand.h declares the hook, so this definition is the
// one the signer links against rather than a file-local function.
static uint8_t g_salt[32];

void ch_rand_bytes(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = g_salt[i < sizeof g_salt ? i : sizeof g_salt - 1];
    }
}

static void load_salt(const uint8_t *salt) {
    memcpy(g_salt, salt, sizeof g_salt);
}

// One vector: a key, the message it signs, the salt, and the signature
// that pair must produce.
typedef struct {
    const char *name;
    const uint8_t *n;
    const uint8_t *d;
    size_t n_len;
    const uint8_t *msg;
    size_t msg_len;
    const uint8_t *salt;
    const uint8_t *sig;
} vector;

static ch_rsa_priv g_key;

static void load_key(const vector *v) {
    memset(&g_key, 0, sizeof g_key);
    memcpy(g_key.n, v->n, v->n_len);
    memcpy(g_key.d, v->d, v->n_len);
    g_key.n_len = v->n_len;
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
        CHECK(rsa_pss_sign(&g_key, msg_hash, small, sizeof small, &small_len) == 0);
        (void)fprintf(stderr, "ok %s refused at this build's modulus bound\n", v->name);
        return;
    }

    load_key(v);
    load_salt(v->salt);
    uint8_t sig[CH_RSA_MODULUS_MAX];
    size_t sig_len = 0;
    CHECK(rsa_pss_sign(&g_key, msg_hash, sig, sizeof sig, &sig_len) == 1);
    CHECK(sig_len == v->n_len);
    CHECK(memcmp(sig, v->sig, v->n_len) == 0);
    CHECK(rsa_pss_verify(v->n, v->n_len, msg_hash, sig, sig_len) == 1);

    uint8_t other_salt[32];
    memset(other_salt, 0x11, sizeof other_salt);
    load_salt(other_salt);
    uint8_t sig2[CH_RSA_MODULUS_MAX];
    size_t sig2_len = 0;
    CHECK(rsa_pss_sign(&g_key, msg_hash, sig2, sizeof sig2, &sig2_len) == 1);
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
// modulus must have.
static void run_refusals(const vector *v) {
    uint8_t sig[CH_RSA_MODULUS_MAX];
    size_t sig_len = 0;
    load_salt(v->salt);
    uint8_t msg_hash[SHA256_LEN];
    memset(msg_hash, 0x42, sizeof msg_hash);

    load_key(v);
    CHECK(rsa_pss_sign(&g_key, msg_hash, sig, v->n_len - 1, &sig_len) == 0); // cap one short
    CHECK(rsa_pss_sign(&g_key, msg_hash, sig, v->n_len, &sig_len) == 1);     // cap exact

    load_key(v);
    g_key.n_len = 248; // one 8-byte step below the RSA-2048 floor
    CHECK(rsa_pss_sign(&g_key, msg_hash, sig, sizeof sig, &sig_len) == 0);
    g_key.n_len = 260; // inside the bounds, not a multiple of 8
    CHECK(rsa_pss_sign(&g_key, msg_hash, sig, sizeof sig, &sig_len) == 0);
    g_key.n_len = CH_RSA_MODULUS_MAX + 8; // one step above the ceiling
    CHECK(rsa_pss_sign(&g_key, msg_hash, sig, sizeof sig, &sig_len) == 0);

    load_key(v);
    g_key.n[g_key.n_len - 1] &= (uint8_t)~1U; // even modulus, no Montgomery inverse
    CHECK(rsa_pss_sign(&g_key, msg_hash, sig, sizeof sig, &sig_len) == 0);

    load_key(v);
    g_key.n[0] &= 0x7f; // top bit clear, so emLen would not be n_len
    CHECK(rsa_pss_sign(&g_key, msg_hash, sig, sizeof sig, &sig_len) == 0);
}

int main(void) {
    const vector vectors[] = {
        {"RSA-2048", rsa_sign_2048_n, rsa_sign_2048_d, sizeof rsa_sign_2048_n, rsa_sign_2048_msg,
         sizeof rsa_sign_2048_msg, rsa_sign_2048_salt, rsa_sign_2048_sig},
        {"RSA-3072", rsa_sign_3072_n, rsa_sign_3072_d, sizeof rsa_sign_3072_n, rsa_sign_3072_msg,
         sizeof rsa_sign_3072_msg, rsa_sign_3072_salt, rsa_sign_3072_sig},
        {"RSA-4096", rsa_sign_4096_n, rsa_sign_4096_d, sizeof rsa_sign_4096_n, rsa_sign_4096_msg,
         sizeof rsa_sign_4096_msg, rsa_sign_4096_salt, rsa_sign_4096_sig},
    };
    for (size_t i = 0; i < sizeof vectors / sizeof vectors[0]; i++) {
        run_vector(&vectors[i]);
    }
    run_refusals(&vectors[0]);

    if (failures != 0) {
        (void)fprintf(stderr, "rsa_sign_test: %d failure(s)\n", failures);
        return 1;
    }
    (void)printf("rsa_sign_test: all checks passed\n");
    return 0;
}
