// The ML-DSA-87 arm of the certificate profile, x509.c under
// CH_PIN_MLDSA, against spec/lean/Spec/X509.lean's `parse .mldsa`, whose
// signature check is spec/lean/Spec/MlDsa.lean's ML-DSA.Verify
// (docs/decisions.md 157). Its own main, because the arm builds under
// PROFILE=cnsa2 alone and no row of bin/diff compiles that build.
//
// The spec signs no ML-DSA-87 certificate, so this side makes them: the
// test-only signer of test/mldsa_sign.c, which Wycheproof's 92 seeded
// signatures hold, signs each one with test/mldsa_cert.h's builder. Each
// run draws fresh keys and fresh name lengths, and holds x509_verify_leaf
// and the spec to one verdict, the leaf key and the epoch included, over
// the same CertificateEntry-list bytes:
//
// - a leaf under the root alone, and a leaf under an intermediate under
//   the root, each accepted, and each refused under a stranger's key;
// - the off-profile shapes: ML-DSA-65's identifier and NULL parameters in
//   the signature and the SPKI identifiers, a key and a signature one
//   byte short and long, a certificate at CH_X509_MAX and one byte over, a
//   third entry, and an intermediate with the leaf's extensions;
// - random byte flips anywhere in a flat list and in a chain.
//
// The domain is the one both sides agree on: lists of the build's one
// algorithm with certificates up to CH_X509_MAX, 7808 bytes, the spec's
// `certMax .mldsa`. A last row holds hsa_signed_content, the bytes
// ML-DSA-87 signs in a CertificateVerify, to the spec's `verifyContent`
// at both transcript hash lengths.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ch_assert.h"
#include "diff_driver.h"
#include "handshake_auth.h"
#include "handshake_message.h"
#include "mldsa_cert.h"
#include "test_random.h" // ch_rand_bytes, which the linked handshake sources import
#include "x509.h"

#if !defined(CH_PIN_MLDSA) || !defined(CH_TRUST_CA)
#error                                                                                             \
    "test/diff_x509_mldsa_test.c checks the ML-DSA-87 CA walk: build it with -DCH_PIN_MLDSA -DCH_TRUST_CA"
#endif

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
static char request[2 * sizeof list + (size_t)2 * MLDSA87_PK_LEN + 64];
static char c_verdict[2 * MLDSA87_PK_LEN + 64];

static void list_put(const uint8_t *cert, size_t n) {
    wbuf w;
    wb_init(&w, list + list_len, sizeof list - list_len);
    wb_u24(&w, (uint32_t)n);
    wb_bytes(&w, cert, n);
    wb_u16(&w, 0);
    if (w.err) {
        die("the list buffer is too small");
    }
    list_len += w.len;
}

// One row: x509_verify_leaf's verdict on the list under ca_key, spelled
// as the spec spells its own, and the spec's verdict on the same bytes.
static void row(const uint8_t ca_key[MLDSA87_PK_LEN]) {
    x509_leaf_info info;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    memset(&info, 0, sizeof info);
    int rc = x509_verify_leaf(list, list_len, ca_key, MLDSA87_PK_LEN, NULL, 0, &info, &alert);
    if (rc == CH_OK) {
        size_t at = (size_t)snprintf(c_verdict, sizeof c_verdict, "ok ");
        at += hex_encode(c_verdict + at, info.key, info.key_len);
        if (info.epoch_ok) {
            (void)snprintf(c_verdict + at, sizeof c_verdict - at, " %u", (unsigned)info.epoch);
        } else {
            (void)snprintf(c_verdict + at, sizeof c_verdict - at, " -");
        }
    } else {
        (void)snprintf(c_verdict, sizeof c_verdict, "ERR x509 reject");
    }
    size_t at = (size_t)snprintf(request, sizeof request, "x509parse mldsa ");
    at += hex_encode(request + at, ca_key, MLDSA87_PK_LEN);
    request[at++] = ' ';
    (void)hex_encode(request + at, list, list_len);
    expect(request, c_verdict);
}

// The server's leaf under issuer, named for it, in shape.
static size_t leaf_cert(uint8_t *out, const mldsa_test_key *issuer, const char *issuer_name,
                        const mldsa_cert_shape *shape) {
    size_t n = mldsa_cert_build(out, leaf_key.pk, "controller-01", issuer, issuer_name, shape);
    if (n == 0) {
        die("the test signer failed");
    }
    return n;
}

// The leaf alone under the root, in shape, verified under the root.
static void flat_row(const mldsa_cert_shape *shape) {
    static uint8_t cert[CH_X509_MAX + 64];
    list_len = 0;
    list_put(cert, leaf_cert(cert, &root, "fleet-root", shape));
    row(root.pk);
}

// The leaf under the intermediate, then the intermediate under the root
// with int_shape, and the third entry when with_third is set.
static void chain_list(const mldsa_cert_shape *int_shape, int with_third) {
    static uint8_t cert[CH_X509_MAX + 64];
    mldsa_cert_shape leaf_shape = {0};
    leaf_shape.name_pad = rng_below(40);
    list_len = 0;
    list_put(cert, leaf_cert(cert, &inter, "fleet-intermediate", &leaf_shape));
    size_t n =
        mldsa_cert_build(cert, inter.pk, "fleet-intermediate", &root, "fleet-root", int_shape);
    if (n == 0) {
        die("the test signer failed");
    }
    list_put(cert, n);
    if (with_third) {
        static const uint8_t third[16] = {0x30, 0x0e};
        list_put(third, sizeof third);
    }
}

static void diff_accept_and_pins(void) {
    mldsa_cert_shape shape = {0};
    shape.name_pad = rng_below(40);
    flat_row(&shape);
    row(stranger.pk);
    mldsa_cert_shape int_shape = {0};
    int_shape.is_ca = 1;
    chain_list(&int_shape, 0);
    row(root.pk);
    row(stranger.pk);
    chain_list(&int_shape, 1);
    row(root.pk);
    // The intermediate under the leaf's extension arm.
    int_shape.is_ca = 0;
    chain_list(&int_shape, 0);
    row(root.pk);
}

static void diff_shapes(void) {
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
        flat_row(&shape);
        shape = (mldsa_cert_shape){0};
        shape.spki_alg = algs[i];
        shape.spki_alg_len = lens[i];
        flat_row(&shape);
    }
    static const int deltas[] = {-1, 1};
    for (int i = 0; i < 2; i++) {
        mldsa_cert_shape shape = {0};
        shape.key_delta = deltas[i];
        flat_row(&shape);
        shape = (mldsa_cert_shape){0};
        shape.sig_delta = deltas[i];
        flat_row(&shape);
    }
    // A certificate at CH_X509_MAX, then one byte over it.
    for (size_t size = CH_X509_MAX; size <= CH_X509_MAX + 1; size++) {
        static uint8_t cert[CH_X509_MAX + 64];
        mldsa_cert_shape shape = {0};
        size_t n = 0;
        for (int step = 0; step < 8 && n != size; step++) {
            n = leaf_cert(cert, &root, "fleet-root", &shape);
            shape.name_pad = (size_t)((long)shape.name_pad + (long)size - (long)n);
        }
        if (n != size) {
            die("no name length reached the certificate size");
        }
        list_len = 0;
        list_put(cert, n);
        row(root.pk);
    }
}

// Random single-byte flips of a flat list and of a chain.
static void diff_flips(void) {
    mldsa_cert_shape int_shape = {0};
    int_shape.is_ca = 1;
    for (int chain = 0; chain < 2; chain++) {
        for (int i = 0; i < 4; i++) {
            if (chain) {
                chain_list(&int_shape, 0);
            } else {
                mldsa_cert_shape shape = {0};
                static uint8_t cert[CH_X509_MAX + 64];
                list_len = 0;
                list_put(cert, leaf_cert(cert, &root, "fleet-root", &shape));
            }
            list[rng_below(list_len)] ^= (uint8_t)(1U << rng_below(8));
            row(root.pk);
        }
    }
}

// hsa_signed_content against the spec's verifyContent, at the SHA-256
// and SHA-384 transcript hash lengths.
static void diff_signed_content(void) {
    static const size_t lens[] = {SHA256_LEN, SHA384_LEN};
    for (size_t i = 0; i < 2; i++) {
        uint8_t hash[SHA384_LEN];
        rng_fill(hash, lens[i]);
        uint8_t content[HSA_SIGNED_CONTENT_MAX];
        size_t n = hsa_signed_content(hash, lens[i], content);
        (void)hex_encode(c_verdict, content, n);
        size_t at = (size_t)snprintf(request, sizeof request, "hs_verify_content ");
        (void)hex_encode(request + at, hash, lens[i]);
        expect(request, c_verdict);
    }
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "spec/lean/.lake/build/bin/diffspec";
    (void)printf("diff x509 mldsa-87: seed 0x%016llx\n", (unsigned long long)rng_seed_from_env());
    uint8_t seed[32];
    rng_fill(seed, sizeof seed);
    mldsa_test_keygen(&root, seed);
    rng_fill(seed, sizeof seed);
    mldsa_test_keygen(&inter, seed);
    rng_fill(seed, sizeof seed);
    mldsa_test_keygen(&leaf_key, seed);
    rng_fill(seed, sizeof seed);
    mldsa_test_keygen(&stranger, seed);
    spawn_spec(path);
    expect("selftest", "ok");
    diff_accept_and_pins();
    diff_shapes();
    diff_flips();
    diff_signed_content();
    if (fclose(to_spec) != 0 || fclose(from_spec) != 0) {
        die("closing spec pipes failed");
    }
    int status = 0;
    (void)waitpid(spec_pid, &status, 0);
    (void)printf("diff x509 mldsa-87: %ld comparisons, C == spec\n", comparisons);
    return 0;
}
