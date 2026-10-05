// bin/widemul_runtime_test: which copy each operation built on ct.h's
// widening multiply runs, under each answer, in a host object
// (docs/decisions.md 87 and 89). Every entry widemul.h dispatches to is
// counted (test/widemul_runtime_count.h), and each operation below runs
// under WIDEMUL_CONSTANT_TIME and WIDEMUL_NOT_STATED and must:
//
//   - under WIDEMUL_CONSTANT_TIME, call the native copies alone;
//   - under WIDEMUL_NOT_STATED, call the files under their own names
//     alone, as many times as the native copies were called above, so no
//     dispatcher took the other copy for one call among many;
//   - compute the same bytes under both, and the published ones where a
//     vector exists.
//
// Every other byte an answer can hold, 0, 3, 0x80 and 0xff, must take the
// decomposition as WIDEMUL_NOT_STATED does: a wiped record direction reads
// 0, and no session passes the others, and the dispatchers must not depend
// on that. The constant-time answer must also run the vector Poly1305,
// and no other answer may.
//
// A record direction and the AEAD entries a session calls take the
// session's ch_cfg.cpu, not an answer (record.h, aead.h), so their rows
// hand them the value cpu_of gives for the answer, and must count the
// same.
//
// widemul_answer, which gives a session its answer, must read
// CH_CPU_CONSTANT_TIME_MULTIPLY alone: the constant-time answer for every
// ch_cfg.cpu that holds the bit, and the other for every value without it.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aead.h"
#include "ch_assert.h"
#include "mlkem.h"
#include "p256.h"
#include "p256_ecdh.h"
#include "p256_sign.h"
#include "rand.h"
#include "record.h"
#include "rsa_sign.h"
#include "rsa_sign_key.h"
#include "sha256.h"
#include "widemul.h"
#include "widemul_runtime_count.h"

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

void ch_rand_bytes(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(i * 13 + 5);
    }
}

static uint8_t nibble(char c) {
    return (uint8_t)(c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10);
}

static void unhex(const char *hex, uint8_t *out) {
    size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
    }
}

static int eq_hex(const uint8_t *got, const char *hex) {
    uint8_t want[64];
    unhex(hex, want);
    return memcmp(got, want, strlen(hex) / 2) == 0;
}

// The largest output any operation below writes: an ML-KEM ciphertext and
// its shared secret.
#define OUT_MAX (MLKEM_CT_LEN + MLKEM_SS_LEN)

// One operation run under the answer widemul, writing its output bytes to
// out and returning how many.
typedef size_t (*operation)(uint8_t widemul, uint8_t out[OUT_MAX]);

// The ch_cfg.cpu value a row hands a call that takes one, for the answer
// widemul: the probe's bit with CH_CPU_CONSTANT_TIME_MULTIPLY for the
// constant-time answer, the probe's bit alone for the other, and for a
// byte that is neither 0, which a wiped record direction holds.
static uint32_t cpu_of(uint8_t widemul) {
    if (widemul == WIDEMUL_CONSTANT_TIME) {
        return CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY;
    }
    return widemul == WIDEMUL_NOT_STATED ? CH_CPU_PROBED : 0;
}

// The key, nonce, associated data and 300 bytes of plaintext both AEAD
// rows seal: 300 bytes hold whole groups of four blocks for the vector
// Poly1305.
#define AEAD_RUN_LEN 300
static const uint8_t aead_run_nonce[AEAD_NONCE] = {7};
static const uint8_t aead_run_aad[13] = {1, 2, 3};

static void aead_run_inputs(uint8_t key[AEAD_KEY], uint8_t pt[AEAD_RUN_LEN]) {
    for (size_t i = 0; i < AEAD_KEY; i++) {
        key[i] = (uint8_t)(0x80 + i);
    }
    for (size_t i = 0; i < AEAD_RUN_LEN; i++) {
        pt[i] = (uint8_t)i;
    }
}

// aead_seal and aead_open, which take the answer: sealed and then opened.
static size_t aead_run(uint8_t widemul, uint8_t out[OUT_MAX]) {
    uint8_t key[AEAD_KEY];
    uint8_t pt[AEAD_RUN_LEN];
    uint8_t back[AEAD_RUN_LEN];
    aead_run_inputs(key, pt);
    aead_seal(widemul, key, aead_run_nonce, aead_run_aad, sizeof aead_run_aad, pt, sizeof pt, out,
              out + sizeof pt);
    CHECK(aead_open(widemul, key, aead_run_nonce, aead_run_aad, sizeof aead_run_aad, out, sizeof pt,
                    out + sizeof pt, back) == 1);
    CHECK(memcmp(back, pt, sizeof pt) == 0);
    return sizeof pt + AEAD_TAG;
}

// aead_seal_cpu and aead_open_cpu, which a record and a QUIC packet call
// with the session's ch_cfg.cpu and which take the answer from its
// multiply bit.
static size_t aead_cpu_run(uint8_t widemul, uint8_t out[OUT_MAX]) {
    uint8_t key[AEAD_KEY];
    uint8_t pt[AEAD_RUN_LEN];
    uint8_t back[AEAD_RUN_LEN];
    aead_run_inputs(key, pt);
    aead_seal_cpu(cpu_of(widemul), key, aead_run_nonce, aead_run_aad, sizeof aead_run_aad, pt,
                  sizeof pt, out, out + sizeof pt);
    CHECK(aead_open_cpu(cpu_of(widemul), key, aead_run_nonce, aead_run_aad, sizeof aead_run_aad,
                        out, sizeof pt, out + sizeof pt, back) == 1);
    CHECK(memcmp(back, pt, sizeof pt) == 0);
    return sizeof pt + AEAD_TAG;
}

// RFC 7748 §5.2's first vector and §6.1's public key.
static size_t x25519_run(uint8_t widemul, uint8_t out[OUT_MAX]) {
    uint8_t k[X25519_LEN];
    uint8_t u[X25519_LEN];
    unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", k);
    unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u);
    CHECK(widemul_x25519(widemul, out, k, u) == 1);
    CHECK(eq_hex(out, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", k);
    widemul_x25519_base(widemul, out + X25519_LEN, k);
    CHECK(eq_hex(out + X25519_LEN,
                 "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    return (size_t)2 * X25519_LEN;
}

// ML-KEM-768 from fixed seeds: key generation, which compresses nothing,
// then encapsulation and decapsulation, which both do.
static size_t mlkem_run(uint8_t widemul, uint8_t out[OUT_MAX]) {
    static uint8_t ek[MLKEM_EK_LEN];
    static uint8_t dk[MLKEM_DK_LEN];
    uint8_t seed[96];
    uint8_t ss[MLKEM_SS_LEN];
    for (size_t i = 0; i < sizeof seed; i++) {
        seed[i] = (uint8_t)(3 * i + 1);
    }
    mlkem_keygen_derand(ek, dk, seed, seed + 32);
    CHECK(mlkem_encaps_derand(widemul, out, out + MLKEM_CT_LEN, ek, seed + 64) == 0);
    mlkem_decaps(widemul, ss, out, dk);
    CHECK(memcmp(ss, out + MLKEM_CT_LEN, MLKEM_SS_LEN) == 0);
    return MLKEM_CT_LEN + MLKEM_SS_LEN;
}

// Two P-256 key pairs, the point check, the exchange in both directions,
// and a signature the independent verifier in p256.c accepts.
static size_t p256_run(uint8_t widemul, uint8_t out[OUT_MAX]) {
    uint8_t draw_a[P256_SCALAR_LEN];
    uint8_t draw_b[P256_SCALAR_LEN];
    uint8_t priv_a[P256_SCALAR_LEN];
    uint8_t priv_b[P256_SCALAR_LEN];
    uint8_t pub_a[P256_POINT_LEN];
    uint8_t pub_b[P256_POINT_LEN];
    uint8_t other[P256_SECRET_LEN];
    uint8_t hash[32];
    memset(draw_a, 0x11, sizeof draw_a);
    memset(draw_b, 0x22, sizeof draw_b);
    memset(hash, 0x5a, sizeof hash);
    CHECK(p256_ecdh_keygen(widemul, draw_a, priv_a, pub_a) == 1);
    CHECK(p256_ecdh_keygen(widemul, draw_b, priv_b, pub_b) == 1);
    CHECK(p256_ecdh_point_valid(widemul, pub_b) == 1);
    CHECK(p256_ecdh(widemul, priv_a, pub_b, out) == 1);
    CHECK(p256_ecdh(widemul, priv_b, pub_a, other) == 1);
    CHECK(memcmp(out, other, P256_SECRET_LEN) == 0);
    size_t sig_len = 0;
    CHECK(p256_sign(widemul, priv_a, hash, out + P256_SECRET_LEN, OUT_MAX - P256_SECRET_LEN,
                    &sig_len) == 1);
    CHECK(p256_ecdsa_verify(pub_a + 1, hash, out + P256_SECRET_LEN, sig_len) == 1);
    return P256_SECRET_LEN + sig_len;
}

// test/rsa_sign_vectors.h's RSA-2048 known answer, signed through the
// dispatcher, and RSASP1 through its own.
static size_t rsa_run(uint8_t widemul, uint8_t out[OUT_MAX]) {
    static ch_rsa_priv key;
    uint8_t hash[SHA256_LEN];
    sha256 h;
    test_rsa_sign_key_2048(&key);
    sha256_init(&h);
    sha256_update(&h, rsa_sign_2048_msg, sizeof rsa_sign_2048_msg);
    sha256_final(&h, hash);
    size_t sig_len = 0;
    CHECK(widemul_rsa_pss_sign(widemul, &key, hash, rsa_sign_2048_salt, out, OUT_MAX, &sig_len) ==
          1);
    CHECK(sig_len == sizeof rsa_sign_2048_sig && memcmp(out, rsa_sign_2048_sig, sig_len) == 0);
    // RSASP1 on the signature's own representative gives the signature.
    uint8_t em[sizeof rsa_sign_2048_n] = {0};
    em[sizeof em - 1] = 2;
    CHECK(widemul_rsa_sp1(widemul, &key, em, out + sig_len) == 1);
    return 2 * sig_len;
}

// One record sealed and opened by the record layer, whose directions carry
// the session's ch_cfg.cpu as its init call writes it (session.h).
static size_t record_run(uint8_t widemul, uint8_t out[OUT_MAX]) {
    uint8_t secret[SHA256_LEN];
    uint8_t pt[200];
    uint8_t back[200 + REC_OVERHEAD];
    memset(secret, 0x33, sizeof secret);
    for (size_t i = 0; i < sizeof pt; i++) {
        pt[i] = (uint8_t)(i ^ 0x5c);
    }
    rec_dir wr;
    rec_dir rd;
    wr.cpu = cpu_of(widemul);
    rd.cpu = cpu_of(widemul);
    rec_dir_init(&wr, secret);
    rec_dir_init(&rd, secret);
    size_t n = 0;
    CHECK(rec_seal(&wr, REC_APPDATA, pt, sizeof pt, out, OUT_MAX, &n) == 0);
    size_t pt_len = 0;
    uint8_t type = 0;
    CHECK(rec_open(&rd, out, n, back, sizeof back, &pt_len, &type) == 0);
    CHECK(type == REC_APPDATA && pt_len == sizeof pt && memcmp(back, pt, sizeof pt) == 0);
    return n;
}

typedef struct {
    unsigned long decomposed;
    unsigned long native;
    unsigned long vector;
} calls;

// Runs op under widemul from zeroed counters, and returns what it called.
static calls counted(operation op, uint8_t widemul, uint8_t out[OUT_MAX], size_t *out_len) {
    widemul_decomposed_calls = 0;
    widemul_native_calls = 0;
    widemul_vector_calls = 0;
    *out_len = op(widemul, out);
    return (calls){widemul_decomposed_calls, widemul_native_calls, widemul_vector_calls};
}

static void check_operation(const char *name, operation op, int runs_vector) {
    static uint8_t stated_out[OUT_MAX];
    static uint8_t other_out[OUT_MAX];
    size_t stated_len = 0;
    size_t other_len = 0;
    calls stated = counted(op, WIDEMUL_CONSTANT_TIME, stated_out, &stated_len);
    calls not_stated = counted(op, WIDEMUL_NOT_STATED, other_out, &other_len);
    int failed = failures;
    CHECK(stated.native > 0 && stated.decomposed == 0);
    CHECK(not_stated.native == 0 && not_stated.decomposed == stated.native);
    CHECK(not_stated.vector == 0);
    CHECK(runs_vector ? stated.vector > 0 : stated.vector == 0);
    CHECK(stated_len == other_len && memcmp(stated_out, other_out, stated_len) == 0);
    // Every byte that is neither answer runs as the decomposition does.
    static const uint8_t neither[] = {0, 3, 0x80, 0xff};
    for (size_t i = 0; i < sizeof neither; i++) {
        calls c = counted(op, neither[i], other_out, &other_len);
        CHECK(c.native == 0 && c.vector == 0 && c.decomposed == not_stated.decomposed);
        CHECK(stated_len == other_len && memcmp(stated_out, other_out, stated_len) == 0);
    }
    (void)printf("widemul_runtime: %-17s %5lu calls into the native copies under the constant-time "
                 "answer, as many into the decomposition under the other%s\n",
                 name, stated.native, failures == failed ? "" : " -- FAILED");
}

// The RSA key test, the one dispatched entry whose other copy multiplies
// nothing: rsa_pss_sign_key_ok reads two public bytes of the modulus, and
// rsa_sign64_key_ok multiplies the key's primes on the native multiply. So
// the dispatcher runs the 64-bit signer's test for the constant-time
// answer alone, and makes no native call for any other byte.
static void check_rsa_key_test(void) {
    static ch_rsa_priv key;
    test_rsa_sign_key_2048(&key);
    widemul_native_calls = 0;
    widemul_decomposed_calls = 0;
    CHECK(widemul_rsa_pss_sign_key_ok(WIDEMUL_CONSTANT_TIME, &key) == 1);
    CHECK(widemul_native_calls == 1 && widemul_decomposed_calls == 0);
    static const uint8_t others[] = {WIDEMUL_NOT_STATED, 0, 3, 0x80, 0xff};
    for (size_t i = 0; i < sizeof others; i++) {
        widemul_native_calls = 0;
        CHECK(widemul_rsa_pss_sign_key_ok(others[i], &key) == 1);
        CHECK(widemul_native_calls == 0);
    }
}

// The answer widemul_answer gives each ch_cfg.cpu: the multiply bit alone
// decides it, at the bit by itself, beside every other bit, and in the two
// values that differ from those by that bit.
static void check_answer(void) {
    static const uint32_t with_bit[] = {CH_CPU_CONSTANT_TIME_MULTIPLY,
                                        CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY, 0xffffffffU};
    static const uint32_t without_bit[] = {0, CH_CPU_PROBED,
                                           0xffffffffU & ~(uint32_t)CH_CPU_CONSTANT_TIME_MULTIPLY};
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    for (size_t i = 0; i < sizeof with_bit / sizeof with_bit[0]; i++) {
        cfg.cpu = with_bit[i];
        CHECK(widemul_answer(&cfg) == WIDEMUL_CONSTANT_TIME);
        cfg.cpu = without_bit[i];
        CHECK(widemul_answer(&cfg) == WIDEMUL_NOT_STATED);
    }
}

int main(void) {
    check_answer();
    check_operation("aead", aead_run, 1);
    check_operation("aead of a session", aead_cpu_run, 1);
    check_operation("x25519", x25519_run, 0);
    check_operation("mlkem", mlkem_run, 0);
    check_operation("p256", p256_run, 0);
    check_operation("rsa", rsa_run, 0);
    check_rsa_key_test();
    check_operation("record", record_run, 1);
    if (failures > 0) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)printf("widemul_runtime: every operation ran the native copies for the constant-time "
                 "answer alone and the decomposition for every other byte\n");
    return 0;
}
