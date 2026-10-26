// The certificate profile under ML-DSA-87 (docs/decisions.md 157): x509.c
// and x509_der.c compiled under CH_PIN_MLDSA, and ch_pubkey_from_pem. Each
// certificate is built at run time by test/mldsa_cert.h and signed by the
// test-only signer, so a mutant inside the grammar is signed again and
// reaches the signature check. Every boundary gets an exact pair: the
// last valid value passes and the first invalid one fails with the alert
// x509.h maps to it.
//
//   - the signature AlgorithmIdentifier: id-ml-dsa-87 with its parameters
//     absent, in both places;
//   - the SPKI: the same identifier, and a key of exactly 2592 bytes;
//   - the signature: any length parses, and mldsa87_verify refuses every
//     length but 4627;
//   - the signed bytes: the TBS with its own header, so a changed byte
//     fails the signature;
//   - the size: a certificate of CH_X509_MAX bytes, and one byte more;
//   - the chain: one or two certificates under slot A or slot B, and the
//     refusals of a third, of an unknown root and of a leaf its
//     intermediate did not sign.
#define CH_X509_CA_TEST 1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "handshake_message.h"
#include "mldsa_cert.h"
#include "pem_armor.h"
#include "x509.h"
#include "x509_ca.h"

#ifndef CH_PIN_MLDSA
#error "test/x509_mldsa_test.c checks the ML-DSA-87 profile: build it with -DCH_PIN_MLDSA"
#endif

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

static mldsa_test_key root;
static mldsa_test_key inter;
static mldsa_test_key leaf_key;
static mldsa_test_key stranger;

static uint8_t list[3 * (CH_X509_MAX + 5) + 64];
static size_t list_len;
static uint8_t alert;
static x509_leaf_info info;

static void list_reset(void) {
    list_len = 0;
}

static void list_put(const uint8_t *cert, size_t n) {
    list[list_len] = (uint8_t)(n >> 16);
    list[list_len + 1] = (uint8_t)(n >> 8);
    list[list_len + 2] = (uint8_t)n;
    memcpy(list + list_len + 3, cert, n);
    list[list_len + 3 + n] = 0;
    list[list_len + 4 + n] = 0;
    list_len += 5 + n;
}

// Verifies the list under slot A, and slot B when b is not NULL, with the
// caller's bad_certificate seed.
static int verify(const uint8_t *a, const uint8_t *b) {
    alert = ALERT_BAD_CERTIFICATE;
    memset(&info, 0, sizeof info);
    return x509_verify_leaf(list, list_len, a, MLDSA87_PK_LEN, b, b == NULL ? 0 : MLDSA87_PK_LEN,
                            &info, &alert);
}

// The leaf of the server key under issuer, in shape, alone in the list.
static size_t put_leaf(const mldsa_test_key *issuer, const mldsa_cert_shape *shape) {
    static uint8_t cert[CH_X509_MAX + 64];
    size_t n = mldsa_cert_build(cert, leaf_key.pk, "controller-01", issuer, "fleet-root", shape);
    list_reset();
    list_put(cert, n);
    return n;
}

static void test_accept(void) {
    mldsa_cert_shape shape = {0};
    put_leaf(&root, &shape);
    CHECK(verify(root.pk, NULL) == CH_OK);
    CHECK(info.key_len == MLDSA87_PK_LEN && memcmp(info.key, leaf_key.pk, MLDSA87_PK_LEN) == 0);
    CHECK(info.ca_slot == 1 && alert == ALERT_BAD_CERTIFICATE);
    CHECK(verify(stranger.pk, root.pk) == CH_OK && info.ca_slot == 2);
    CHECK(verify(stranger.pk, NULL) == CH_EAUTH && alert == ALERT_UNKNOWN_CA);
}

// The AlgorithmIdentifier of the signature and of the key: id-ml-dsa-87
// with parameters absent passes, and ML-DSA-65's identifier, or the same
// identifier with NULL parameters, is off-profile.
static void test_algorithms(void) {
    static const uint8_t mldsa65[] = {0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48,
                                      0x01, 0x65, 0x03, 0x04, 0x03, 0x12};
    static const uint8_t with_null[] = {0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                        0x65, 0x03, 0x04, 0x03, 0x13, 0x05, 0x00};
    const uint8_t *algs[] = {mldsa65, with_null};
    const size_t lens[] = {sizeof mldsa65, sizeof with_null};
    for (int i = 0; i < 2; i++) {
        mldsa_cert_shape shape = {0};
        shape.sigalg = algs[i];
        shape.sigalg_len = lens[i];
        put_leaf(&root, &shape);
        CHECK(verify(root.pk, NULL) == CH_EPROTO && alert == ALERT_UNSUPPORTED_CERTIFICATE);
        shape = (mldsa_cert_shape){0};
        shape.spki_alg = algs[i];
        shape.spki_alg_len = lens[i];
        put_leaf(&root, &shape);
        CHECK(verify(root.pk, NULL) == CH_EPROTO && alert == ALERT_UNSUPPORTED_CERTIFICATE);
    }
}

// The key is 2592 bytes exactly; 2591 and 2593 are off-profile. The
// signature parses at any length, and only 4627 bytes verify.
static void test_lengths(void) {
    static const int key_deltas[] = {-1, 1};
    for (int i = 0; i < 2; i++) {
        mldsa_cert_shape shape = {0};
        shape.key_delta = key_deltas[i];
        put_leaf(&root, &shape);
        CHECK(verify(root.pk, NULL) == CH_EPROTO && alert == ALERT_UNSUPPORTED_CERTIFICATE);
    }
    static const int sig_deltas[] = {-1, 1};
    for (int i = 0; i < 2; i++) {
        mldsa_cert_shape shape = {0};
        shape.sig_delta = sig_deltas[i];
        put_leaf(&root, &shape);
        CHECK(verify(root.pk, NULL) == CH_EAUTH && alert == ALERT_UNKNOWN_CA);
    }
}

// The signature covers the TBS with its header. The signer signs that
// TLV whole, as OpenSSL does, so test_accept fails a walk that verifies
// over the TBS content alone. Here a byte flipped in the subject name
// fails the signature.
static void test_signed_bytes(void) {
    mldsa_cert_shape shape = {0};
    size_t n = put_leaf(&root, &shape);
    CHECK(verify(root.pk, NULL) == CH_OK);
    // The last byte of the name "controller-01", ahead of the key.
    size_t at = 0;
    for (size_t i = 0; i + 13 <= n; i++) {
        if (memcmp(list + 3 + i, "controller-01", 13) == 0) {
            at = 3 + i + 12;
        }
    }
    CHECK(at > 0);
    list[at] ^= 1;
    CHECK(verify(root.pk, NULL) == CH_EAUTH && alert == ALERT_UNKNOWN_CA);
}

// A certificate of CH_X509_MAX bytes passes, and one byte more is refused
// before it is parsed.
static void test_size(void) {
    mldsa_cert_shape shape = {0};
    static uint8_t cert[CH_X509_MAX + 64];
    for (size_t want = CH_X509_MAX; want <= CH_X509_MAX + 1; want++) {
        size_t n = 0;
        shape.name_pad = 0;
        for (int step = 0; step < 8 && n != want; step++) {
            n = mldsa_cert_build(cert, leaf_key.pk, "controller-01", &root, "fleet-root", &shape);
            shape.name_pad = (size_t)((long)shape.name_pad + (long)want - (long)n);
        }
        CHECK(n == want);
        list_reset();
        list_put(cert, n);
        int rc = verify(root.pk, NULL);
        CHECK(want == CH_X509_MAX ? rc == CH_OK
                                  : rc == CH_EPROTO && alert == ALERT_BAD_CERTIFICATE);
    }
}

static void test_chains(void) {
    static uint8_t leaf_cert[CH_X509_MAX + 64];
    static uint8_t int_cert[CH_X509_MAX + 64];
    mldsa_cert_shape leaf_shape = {0};
    mldsa_cert_shape int_shape = {0};
    int_shape.is_ca = 1;
    size_t leaf_n = mldsa_cert_build(leaf_cert, leaf_key.pk, "controller-01", &inter,
                                     "fleet-intermediate", &leaf_shape);
    size_t int_n =
        mldsa_cert_build(int_cert, inter.pk, "fleet-intermediate", &root, "fleet-root", &int_shape);
    list_reset();
    list_put(leaf_cert, leaf_n);
    list_put(int_cert, int_n);
    CHECK(verify(root.pk, NULL) == CH_OK && info.ca_slot == 1);
    CHECK(memcmp(info.key, leaf_key.pk, MLDSA87_PK_LEN) == 0);
    CHECK(verify(stranger.pk, NULL) == CH_EAUTH && alert == ALERT_UNKNOWN_CA);

    // A third entry, which the profile never admits.
    static const uint8_t third[16] = {0x30, 0x0e};
    list_put(third, sizeof third);
    CHECK(verify(root.pk, NULL) == CH_EPROTO && alert == ALERT_UNSUPPORTED_CERTIFICATE);

    // The pins vouch for the intermediate, and the leaf's signature is
    // the stranger's.
    leaf_n = mldsa_cert_build(leaf_cert, leaf_key.pk, "controller-01", &stranger,
                              "fleet-intermediate", &leaf_shape);
    list_reset();
    list_put(leaf_cert, leaf_n);
    list_put(int_cert, int_n);
    CHECK(verify(root.pk, NULL) == CH_EAUTH && alert == ALERT_BAD_CERTIFICATE);
}

// ch_pubkey_from_pem gives the 2592-byte key of an ML-DSA-87 root, and
// refuses a leaf, which is no CA.
static void test_provision(void) {
    static uint8_t cert[CH_X509_MAX + 64];
    static uint8_t pem[CH_PEM_MAX + 64];
    static uint8_t der[CH_X509_MAX];
    static uint8_t key[CH_X509_KEY_MAX];
    mldsa_cert_shape shape = {0};
    shape.is_ca = 1;
    size_t n = mldsa_cert_build(cert, root.pk, "fleet-root", &root, "fleet-root", &shape);
    size_t pem_len = pem_armor(cert, n, 64, "\n", pem);
    size_t key_len = 0;
    CHECK(ch_pubkey_from_pem(pem, pem_len, der, key, &key_len) == CH_OK);
    CHECK(key_len == MLDSA87_PK_LEN && memcmp(key, root.pk, MLDSA87_PK_LEN) == 0);
    shape.is_ca = 0;
    n = mldsa_cert_build(cert, leaf_key.pk, "controller-01", &root, "fleet-root", &shape);
    pem_len = pem_armor(cert, n, 64, "\n", pem);
    CHECK(ch_pubkey_from_pem(pem, pem_len, der, key, &key_len) == CH_EINVAL && key_len == 0);
}

int main(void) {
    uint8_t seed[32] = {0};
    seed[0] = 1;
    mldsa_test_keygen(&root, seed);
    seed[0] = 2;
    mldsa_test_keygen(&inter, seed);
    seed[0] = 3;
    mldsa_test_keygen(&leaf_key, seed);
    seed[0] = 4;
    mldsa_test_keygen(&stranger, seed);
    test_accept();
    test_algorithms();
    test_lengths();
    test_signed_bytes();
    test_size();
    test_chains();
    test_provision();
    if (failures > 0) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)printf("x509_mldsa_test: all checks passed\n");
    return 0;
}
