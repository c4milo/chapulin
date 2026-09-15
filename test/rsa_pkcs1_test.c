// RSASSA-PKCS1-v1_5 verification against openssl-produced vectors: valid
// RSA-2048 and RSA-3072 signatures over SHA-256 and SHA-384 digests
// verify, and each documented tamper or malformed input is refused. Its
// own binary with a private main, like rsa_test and sha3_test. The
// digests are recomputed here with the tree's own SHA-256 and SHA-384
// and checked against the openssl digests the vectors carry, so the
// SHA-384 the webpki build hashes certificates with is measured against
// openssl on the way.
//
// test/gen_rsa_pkcs1_vectors.py produced test/rsa_pkcs1_vectors.h and
// quotes every openssl command.
#include <stdio.h>
#include <string.h>

#include "rsa.h"
#include "rsa_pkcs1.h"
#include "rsa_pkcs1_vectors.h"
#include "sha256.h"
#include "sha512.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

// The modulus size gate: 256 bytes is the smallest accepted, 384 the
// largest, and the step is 8. A buffer this wide lets the refused sizes
// above 384 be passed without reading past an array.
#define MODULUS_MIN 256
#define MODULUS_MAX 384
#define OVER_MAX_LEN (MODULUS_MAX + 8)
#define NOT_A_STEP_LEN (MODULUS_MIN + 4)

// One valid vector: the modulus, the message and openssl's digest of it,
// and the signature. The test hashes the message itself and requires
// the tree's digest to equal openssl's before it verifies anything.
typedef struct {
    const uint8_t *n;
    size_t n_len;
    const char *message;
    const uint8_t *digest;
    size_t digest_len;
    const uint8_t *sig;
    size_t sig_len;
} vector;

static const vector vectors[] = {
    {n2048, sizeof n2048, rsa2048_sha256_message, rsa2048_sha256_digest,
     sizeof rsa2048_sha256_digest, rsa2048_sha256_sig, sizeof rsa2048_sha256_sig},
    {n2048, sizeof n2048, rsa2048_sha384_message, rsa2048_sha384_digest,
     sizeof rsa2048_sha384_digest, rsa2048_sha384_sig, sizeof rsa2048_sha384_sig},
    {n3072, sizeof n3072, rsa3072_sha256_message, rsa3072_sha256_digest,
     sizeof rsa3072_sha256_digest, rsa3072_sha256_sig, sizeof rsa3072_sha256_sig},
    {n3072, sizeof n3072, rsa3072_sha384_message, rsa3072_sha384_digest,
     sizeof rsa3072_sha384_digest, rsa3072_sha384_sig, sizeof rsa3072_sha384_sig},
};

// Hashes v->message with the tree's own SHA-256 or SHA-384, chosen by
// v->digest_len, into out. Returns the digest length.
static size_t hash_message(const vector *v, uint8_t out[SHA384_LEN]) {
    const uint8_t *message = (const uint8_t *)v->message;
    size_t message_len = strlen(v->message);
    if (v->digest_len == SHA256_LEN) {
        sha256_of(message, message_len, out);
    } else {
        sha384_of(message, message_len, out);
    }
    return v->digest_len;
}

// Every vector verifies, and the tree's digest equals openssl's.
static void test_valid(void) {
    for (size_t i = 0; i < sizeof vectors / sizeof vectors[0]; i++) {
        const vector *v = &vectors[i];
        uint8_t digest[SHA384_LEN];
        size_t digest_len = hash_message(v, digest);
        CHECK(memcmp(digest, v->digest, digest_len) == 0);
        CHECK(rsa_pkcs1_verify(v->n, v->n_len, digest, digest_len, v->sig, v->sig_len) == 1);
        CHECK(rsa_pkcs1_verify(v->n, v->n_len, v->digest, v->digest_len, v->sig, v->sig_len) == 1);
    }
}

// The tamper set, applied to every vector: a flipped signature byte, a
// flipped digest byte, the wrong digest length, and sig_len != n_len.
static void test_tampered(void) {
    for (size_t i = 0; i < sizeof vectors / sizeof vectors[0]; i++) {
        const vector *v = &vectors[i];

        uint8_t bad_sig[MODULUS_MAX];
        memcpy(bad_sig, v->sig, v->sig_len);
        bad_sig[v->sig_len / 2] ^= 0x01;
        CHECK(rsa_pkcs1_verify(v->n, v->n_len, v->digest, v->digest_len, bad_sig, v->sig_len) == 0);

        uint8_t bad_digest[SHA384_LEN];
        memcpy(bad_digest, v->digest, v->digest_len);
        bad_digest[0] ^= 0x01;
        CHECK(rsa_pkcs1_verify(v->n, v->n_len, bad_digest, v->digest_len, v->sig, v->sig_len) == 0);

        // The other supported length, and lengths no supported hash has,
        // over the same digest bytes. A shorter length reads a prefix of
        // the real digest; SHA384_LEN over a SHA-256 vector reads past
        // it, so that pairing passes a local copy padded to 48 bytes.
        uint8_t padded[SHA384_LEN] = {0};
        memcpy(padded, v->digest, v->digest_len);
        size_t other_len = v->digest_len == SHA256_LEN ? SHA384_LEN : SHA256_LEN;
        CHECK(rsa_pkcs1_verify(v->n, v->n_len, padded, other_len, v->sig, v->sig_len) == 0);
        CHECK(rsa_pkcs1_verify(v->n, v->n_len, padded, 0, v->sig, v->sig_len) == 0);
        CHECK(rsa_pkcs1_verify(v->n, v->n_len, padded, SHA256_LEN - 1, v->sig, v->sig_len) == 0);
        CHECK(rsa_pkcs1_verify(v->n, v->n_len, padded, SHA256_LEN + 1, v->sig, v->sig_len) == 0);
        CHECK(rsa_pkcs1_verify(v->n, v->n_len, padded, SHA384_LEN - 1, v->sig, v->sig_len) == 0);

        // sig_len != n_len, one byte either side.
        CHECK(rsa_pkcs1_verify(v->n, v->n_len, v->digest, v->digest_len, v->sig, v->sig_len - 1) ==
              0);
        uint8_t long_sig[MODULUS_MAX + 1] = {0};
        memcpy(long_sig, v->sig, v->sig_len);
        CHECK(rsa_pkcs1_verify(v->n, v->n_len, v->digest, v->digest_len, long_sig,
                               v->sig_len + 1) == 0);

        // A signature at or above the modulus is out of RSAVP1's range.
        CHECK(rsa_pkcs1_verify(v->n, v->n_len, v->digest, v->digest_len, v->n, v->n_len) == 0);
    }
}

// The modulus gate, at its exact boundaries: 255 bytes is refused and
// 256 accepted (the RSA-2048 vectors), 384 accepted (the RSA-3072
// vectors) and 392 refused, and a length between steps is refused. The
// refused sizes pass a wide buffer whose first bytes are the real
// modulus and signature, so the gate alone decides.
static void test_modulus_gate(void) {
    const vector *v = &vectors[0]; // n2048, SHA-256
    CHECK(v->n_len == MODULUS_MIN);
    CHECK(rsa_pkcs1_verify(v->n, MODULUS_MIN, v->digest, v->digest_len, v->sig, MODULUS_MIN) == 1);
    CHECK(rsa_pkcs1_verify(v->n, MODULUS_MIN - 1, v->digest, v->digest_len, v->sig,
                           MODULUS_MIN - 1) == 0);

    const vector *w = &vectors[2]; // n3072, SHA-256
    CHECK(w->n_len == MODULUS_MAX);
    CHECK(rsa_pkcs1_verify(w->n, MODULUS_MAX, w->digest, w->digest_len, w->sig, MODULUS_MAX) == 1);
    uint8_t wide_n[OVER_MAX_LEN] = {0};
    uint8_t wide_sig[OVER_MAX_LEN] = {0};
    memcpy(wide_n, w->n, w->n_len);
    memcpy(wide_sig, w->sig, w->sig_len);
    wide_n[OVER_MAX_LEN - 1] = 0x01; // odd, so only the size gate refuses it
    CHECK(rsa_pkcs1_verify(wide_n, OVER_MAX_LEN, w->digest, w->digest_len, wide_sig,
                           OVER_MAX_LEN) == 0);
    wide_n[NOT_A_STEP_LEN - 1] = 0x01;
    CHECK(rsa_pkcs1_verify(wide_n, NOT_A_STEP_LEN, w->digest, w->digest_len, wide_sig,
                           NOT_A_STEP_LEN) == 0);

    // An even modulus is refused before any arithmetic runs.
    uint8_t even_n[MODULUS_MAX];
    memcpy(even_n, w->n, w->n_len);
    even_n[w->n_len - 1] &= (uint8_t)~0x01;
    CHECK(rsa_pkcs1_verify(even_n, w->n_len, w->digest, w->digest_len, w->sig, w->sig_len) == 0);
}

// Algorithm confusion: an RSA-PSS signature under the same key over the
// same digest is a valid signature for rsa_pss_verify and must be
// refused here, because its encoded message is a PSS encoding, not the
// PKCS#1 v1.5 one. The other direction holds too: rsa_pss_verify
// refuses the PKCS#1 v1.5 signature.
static void test_pss_refused(void) {
    const vector *v = &vectors[0]; // n2048, SHA-256, message one
    CHECK(sizeof rsa2048_sha256_pss_sig == v->n_len);
    CHECK(rsa_pss_verify(v->n, v->n_len, v->digest, rsa2048_sha256_pss_sig,
                         sizeof rsa2048_sha256_pss_sig) == 1);
    CHECK(rsa_pkcs1_verify(v->n, v->n_len, v->digest, v->digest_len, rsa2048_sha256_pss_sig,
                           sizeof rsa2048_sha256_pss_sig) == 0);
    CHECK(rsa_pss_verify(v->n, v->n_len, v->digest, v->sig, v->sig_len) == 0);
}

int main(void) {
    test_valid();
    test_tampered();
    test_modulus_gate();
    test_pss_refused();
    if (failures > 0) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)printf("rsa_pkcs1_test: all checks passed\n");
    return 0;
}
