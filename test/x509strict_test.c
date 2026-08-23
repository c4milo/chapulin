// Grammar strictness for the profiled certificate parser (issue #22):
// every boundary in the profile gets an exact pair — the last valid
// encoding passes and the first invalid one fails with the alert
// x509.h maps to it. Mutants come from the good vector by splices
// (test/x509mut.h) that rebuild every enclosing DER length, so the
// cases survive vector regeneration without hand-patched offsets. A
// mutant that stays inside the grammar proves it by reaching
// signature verification (CH_EAUTH, unknown_ca) — its TBS bytes no
// longer match the CA signature — while a grammar reject never gets
// that far. Its own binary with a private main, like the other test
// mains; compiled once per PIN variant so each build tests its grammar.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "cfg.h"
#include "ch_assert.h"
#include "hsmsg.h"
#include "x509.h"
#include "x509_vectors.h"
#include "x509mut.h"

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

// The build's own vectors, plus the other build's leaf so the
// wrong-algorithm case runs against real bytes.
#ifdef CH_PIN_ECDSA
static const uint8_t *const good_cert = certv_leaf_p256;
static const size_t good_cert_len = sizeof certv_leaf_p256;
static const uint8_t *const good_key = certv_leaf_p256_key;
static const size_t good_key_len = sizeof certv_leaf_p256_key;
static const uint8_t *const ca_key = certv_ca_p256_xy;
static const size_t ca_key_len = sizeof certv_ca_p256_xy;
static const uint8_t *const other_build_cert = certv_leaf_rsa;
static const size_t other_build_cert_len = sizeof certv_leaf_rsa;
static const uint8_t *const chain_int = certv_int_p256;
static const size_t chain_int_len = sizeof certv_int_p256;
static const uint8_t *const chain_leaf = certv_leaf_via_int_p256;
static const size_t chain_leaf_len = sizeof certv_leaf_via_int_p256;
static const uint8_t *const chain_leaf_key = certv_leaf_via_int_p256_key;
static const size_t chain_leaf_key_len = sizeof certv_leaf_via_int_p256_key;
#else
static const uint8_t *const good_cert = certv_leaf_rsa;
static const size_t good_cert_len = sizeof certv_leaf_rsa;
static const uint8_t *const good_key = certv_leaf_rsa_key;
static const size_t good_key_len = sizeof certv_leaf_rsa_key;
static const uint8_t *const ca_key = certv_ca_rsa_modulus;
static const size_t ca_key_len = sizeof certv_ca_rsa_modulus;
static const uint8_t *const other_build_cert = certv_leaf_p256;
static const size_t other_build_cert_len = sizeof certv_leaf_p256;
static const uint8_t *const chain_int = certv_int_rsa;
static const size_t chain_int_len = sizeof certv_int_rsa;
static const uint8_t *const chain_leaf = certv_leaf_via_int_rsa;
static const size_t chain_leaf_len = sizeof certv_leaf_via_int_rsa;
static const uint8_t *const chain_leaf_key = certv_leaf_via_int_rsa_key;
static const size_t chain_leaf_key_len = sizeof certv_leaf_via_int_rsa_key;
#endif

static const uint8_t oid_ku[3] = {0x55, 0x1d, 0x0f};
static const uint8_t oid_eku[3] = {0x55, 0x1d, 0x25};
static const uint8_t oid_bc[3] = {0x55, 0x1d, 0x13};

static uint8_t wrong_ca[sizeof certv_ca_rsa_modulus];
static uint8_t mutant_a[CH_X509_MAX];
static uint8_t mutant_b[CH_X509_MAX];

// List buffer for the chain cases. Sized for the largest case built
// anywhere in this file — three cap-sized entries — so it holds under
// either value of CH_X509_MAX.
static uint8_t chain_list[3 * (CH_X509_MAX + 5) + 16];

static uint8_t last_alert;
static x509_leaf_info last_info;

// Runs the verifier over raw CertificateEntry-list bytes, seeding the
// alert with bad_certificate the way handshake.c will.
static int run_list_slots(const uint8_t *list, size_t n, const uint8_t *slot_a, size_t a_len,
                          const uint8_t *slot_b, size_t b_len) {
    last_alert = ALERT_BAD_CERTIFICATE;
    memset(&last_info, 0, sizeof last_info);
    return x509_verify_leaf(list, n, slot_a, a_len, slot_b, b_len, &last_info, &last_alert);
}

// Wraps one certificate in a one-entry list and verifies it against
// the given CA slots.
static int run_slots(const uint8_t *cert, size_t n, const uint8_t *slot_a, size_t a_len,
                     const uint8_t *slot_b, size_t b_len) {
    static uint8_t list[CH_X509_MAX + 5];
    if (n > CH_X509_MAX) {
        mut_die("mutant outgrew the list buffer");
    }
    return run_list_slots(list, put_entry(list, cert, n), slot_a, a_len, slot_b, b_len);
}

static int run_cert(const uint8_t *cert, size_t n) {
    return run_slots(cert, n, ca_key, ca_key_len, NULL, 0);
}

// Mutation helpers over the good leaf, plus the accept, list,
// two-entry chain, and SubjectPublicKeyInfo cases, split into their
// own headers for file size.
#include "x509chain_tests.h"
#include "x509epoch.h"
#include "x509spki.h"

static void test_outer_and_serial(void) {
    tlv_shape outer;
    tlv_read(good_cert, good_cert_len, &outer);

    // The outer length with one octet too many; the minimal vector
    // itself is the valid side (test_accept).
    memcpy(mutant_a,
           (const uint8_t[]){0x30, 0x83, 0x00, (uint8_t)(outer.content_len >> 8),
                             (uint8_t)outer.content_len},
           5);
    memcpy(mutant_a + 5, good_cert + outer.header_len, outer.content_len);
    CHECK(rejected(mutant_a, outer.content_len + 5, ALERT_BAD_CERTIFICATE));

    // tbs.version absent, then present with the wrong value ([0]
    // EXPLICIT INTEGER value byte: v2, not v3).
    size_t version = tbs_field(good_cert, good_cert_len, 0);
    size_t n = mutate(version, tlv_total(good_cert, good_cert_len, version), NULL, 0);
    CHECK(rejected(mutant_a, n, ALERT_BAD_CERTIFICATE));
    CHECK(rejected(mutant_a, patch2(mutant_a, version + 3, 0x01, 0x01), ALERT_BAD_CERTIFICATE));

    // serialNumber: 21 content bytes — the required 0x00 pad plus a
    // 20-byte top-bit-set value — is the largest admissible encoding;
    // a pad plus a 21-byte value is over the RFC cap, and so is a
    // 21-byte unpadded value.
    CHECK(grammar_ok(mutant_a, serial_case(1, 0x80, 20)));
    CHECK(rejected(mutant_a, serial_case(1, 0x80, 21), ALERT_BAD_CERTIFICATE));
    CHECK(rejected(mutant_a, serial_case(0, 0x7f, 21), ALERT_BAD_CERTIFICATE));

    // Zero, negative, and a pad the value does not need.
    CHECK(rejected(mutant_a, serial_case(0, 0x00, 1), ALERT_BAD_CERTIFICATE));
    CHECK(rejected(mutant_a, serial_case(0, 0x81, 1), ALERT_BAD_CERTIFICATE));
    CHECK(rejected(mutant_a, serial_case(1, 0x7f, 1), ALERT_BAD_CERTIFICATE));
}

#ifndef CH_PIN_ECDSA
// First NULL TLV (05 00) inside [lo, hi); the PSS AlgorithmIdentifier
// holds exactly two and no other 0x05 byte precedes them.
static size_t find_null(const uint8_t *cert, size_t lo, size_t hi) {
    for (size_t i = lo; i + 1 < hi; i++) {
        if (cert[i] == 0x05 && cert[i + 1] == 0x00) {
            return i;
        }
    }
    mut_die("no NULL parameters found");
}
#endif

static void test_sigalg_and_time(void) {
    size_t inner = tbs_field(good_cert, good_cert_len, 2);
    size_t inner_size = tlv_total(good_cert, good_cert_len, inner);
    size_t outer_alg = nth_child(good_cert, good_cert_len, 0, 1);

    // One OID byte off the pinned constant, in each of the two places
    // the AlgorithmIdentifier appears.
    size_t n = patch2(mutant_a, inner + 4, good_cert[inner + 4] ^ 1U, good_cert[inner + 5]);
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));
    n = patch2(mutant_a, outer_alg + 4, good_cert[outer_alg + 4] ^ 1U, good_cert[outer_alg + 5]);
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));

#ifdef CH_PIN_ECDSA
    // ecdsa-with-SHA256 parameters must stay absent: NULL is rejected.
    uint8_t with_null[14] = {0x30, 0x0c};
    memcpy(with_null + 2, good_cert + inner + 2, 10); // the OID TLV
    with_null[12] = 0x05;                             // NULL parameters; [13] stays 0x00
    CHECK(rejected(mutant_a, mutate(inner, inner_size, with_null, 14),
                   ALERT_UNSUPPORTED_CERTIFICATE));
#else
    // The RFC 4055 absent-params variant: remove both NULLs from the
    // inner SHA-256 identifiers and rebuild every enclosing length.
    n = mutate(find_null(good_cert, inner, inner + inner_size), 2, NULL, 0);
    size_t inner2 = tbs_field(mutant_a, n, 2);
    size_t null2 = find_null(mutant_a, inner2, inner2 + tlv_total(mutant_a, n, inner2));
    n = splice(mutant_b, mutant_a, n, null2, 2, NULL, 0);
    CHECK(rejected(mutant_b, n, ALERT_UNSUPPORTED_CERTIFICATE));
#endif

    size_t not_before =
        nth_child(good_cert, good_cert_len, tbs_field(good_cert, good_cert_len, 4), 0);
    size_t not_before_size = tlv_total(good_cert, good_cert_len, not_before);
    uint8_t repl[17];

    // GeneralizedTime, length 15: the other admitted Time shape.
    memcpy(repl, (const uint8_t[]){0x18, 15, '2', '0'}, 4);
    memcpy(repl + 4, good_cert + not_before + 2, 13);
    CHECK(grammar_ok(mutant_a, mutate(not_before, not_before_size, repl, 17)));

    // The same 15-byte GeneralizedTime ending in a digit, not Z.
    repl[16] = '0';
    CHECK(rejected(mutant_a, mutate(not_before, not_before_size, repl, 17), ALERT_BAD_CERTIFICATE));

    // The GeneralizedTime tag on a 13-byte body.
    CHECK(rejected(mutant_a, patch2(mutant_a, not_before, 0x18, 13), ALERT_BAD_CERTIFICATE));

    // UTCTime with one byte too many.
    memcpy(repl, (const uint8_t[]){0x17, 14}, 2);
    memcpy(repl + 2, good_cert + not_before + 2, 12);
    memcpy(repl + 14, "0Z", 2);
    CHECK(rejected(mutant_a, mutate(not_before, not_before_size, repl, 16), ALERT_BAD_CERTIFICATE));

    // UTCTime without the trailing Z.
    n = patch2(mutant_a, not_before + 13, good_cert[not_before + 13], '0');
    CHECK(rejected(mutant_a, n, ALERT_BAD_CERTIFICATE));
}

static void test_decoded_extensions(void) {
    size_t ku = find_ext(good_cert, good_cert_len, oid_ku);
    size_t value = ext_child(good_cert, good_cert_len, ku, 0x04);
    tlv_shape v;
    tlv_read(good_cert + value, good_cert_len - value, &v);
    size_t content = value + v.header_len; // the BIT STRING 03 02 07 80
    size_t n;

    // keyUsage: digitalSignature plus one more bit is still canonical
    // named-bit DER; so is a two-defined-octet form with its last bit
    // set; three defined octets are over the named-bit bound.
    CHECK(grammar_ok(mutant_a, patch2(mutant_a, content + 2, 0x06, 0xc0)));
    n = mutate(content, v.content_len, (const uint8_t[]){0x03, 0x03, 0x07, 0x80, 0x80}, 5);
    CHECK(grammar_ok(mutant_a, n));
    n = mutate(content, v.content_len, (const uint8_t[]){0x03, 0x04, 0x07, 0x80, 0x00, 0x80}, 6);
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));

    // A trailing zero octet canonical DER strips.
    n = mutate(content, v.content_len, (const uint8_t[]){0x03, 0x03, 0x00, 0x80, 0x00}, 5);
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));

    // Nonzero bits below the unused-bits count; an unused-bits count
    // that leaves the lowest defined bit zero; no digitalSignature.
    CHECK(rejected(mutant_a, patch2(mutant_a, content + 2, 0x06, 0x81),
                   ALERT_UNSUPPORTED_CERTIFICATE));
    CHECK(rejected(mutant_a, patch2(mutant_a, content + 2, 0x06, 0x80),
                   ALERT_UNSUPPORTED_CERTIFICATE));
    CHECK(rejected(mutant_a, patch2(mutant_a, content + 2, 0x06, 0x40),
                   ALERT_UNSUPPORTED_CERTIFICATE));

    // A duplicate keyUsage: a second, byte-identical copy of the
    // whole extension. Both copies decode fine on their own; only the
    // RFC 5280 §4.2 one-per-extnID rule rejects the pair.
    n = mutate(ku, 0, good_cert + ku, tlv_total(good_cert, good_cert_len, ku));
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));

    // keyUsage absent entirely while extendedKeyUsage stays: the leaf
    // needs both (mask 1|2), the case that hid the mask bug.
    n = mutate(ku, tlv_total(good_cert, good_cert_len, ku), NULL, 0);
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));

    // critical FALSE spelled out: the DEFAULT must be absent in DER.
    size_t crit = ext_child(good_cert, good_cert_len, ku, 0x01);
    CHECK(rejected(mutant_a, patch2(mutant_a, crit + 1, 0x01, 0x00), ALERT_BAD_CERTIFICATE));

    // extendedKeyUsage: id-kp-clientAuth in place of serverAuth (the
    // last OID arc differs), then serverAuth plus a second purpose.
    size_t eku = find_ext(good_cert, good_cert_len, oid_eku);
    value = ext_child(good_cert, good_cert_len, eku, 0x04);
    tlv_read(good_cert + value, good_cert_len - value, &v);
    content = value + v.header_len;
    size_t last = content + v.content_len - 2;
    n = patch2(mutant_a, last, good_cert[last], 0x02);
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));
    uint8_t two[22] = {0x30, 0x14};
    memcpy(two + 2, good_cert + content + 2, 10); // the serverAuth OID TLV
    memcpy(two + 12, good_cert + content + 2, 10);
    two[21] = 0x02; // last arc of the second purpose: clientAuth
    CHECK(
        rejected(mutant_a, mutate(content, v.content_len, two, 22), ALERT_UNSUPPORTED_CERTIFICATE));

    // A duplicate extendedKeyUsage, byte-identical like the keyUsage
    // pair above.
    n = mutate(eku, 0, good_cert + eku, tlv_total(good_cert, good_cert_len, eku));
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));

    // basicConstraints CA=TRUE.
    size_t bc_value =
        ext_child(good_cert, good_cert_len, find_ext(good_cert, good_cert_len, oid_bc), 0x04);
    tlv_read(good_cert + bc_value, good_cert_len - bc_value, &v);
    n = mutate(bc_value + v.header_len, v.content_len,
               (const uint8_t[]){0x30, 0x03, 0x01, 0x01, 0xff}, 5);
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));
}

static void test_ext_shape(void) {
    size_t wrap = tbs_field(good_cert, good_cert_len, 7);
    size_t wrap_size = tlv_total(good_cert, good_cert_len, wrap);
    tlv_shape w;
    tlv_read(good_cert + wrap, good_cert_len - wrap, &w);
    size_t n;

    // The [3] wrapper's short-form length re-encoded long-form.
    uint8_t inflated[300] = {0xa3, 0x81};
    inflated[2] = (uint8_t)w.content_len;
    memcpy(inflated + 3, good_cert + wrap + w.header_len, w.content_len);
    n = mutate(wrap, wrap_size, inflated, w.content_len + 3);
    CHECK(rejected(mutant_a, n, ALERT_BAD_CERTIFICATE));

    // An empty Extensions SEQUENCE: the type is SIZE (1..MAX). Then no
    // extensions wrapper at all.
    n = mutate(wrap, wrap_size, (const uint8_t[]){0xa3, 0x02, 0x30, 0x00}, 4);
    CHECK(rejected(mutant_a, n, ALERT_BAD_CERTIFICATE));
    CHECK(rejected(mutant_a, mutate(wrap, wrap_size, NULL, 0), ALERT_BAD_CERTIFICATE));

    // An unknown critical extension is rejected; the same extension
    // without the critical flag is skipped.
    static const uint8_t critical_unknown[] = {0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x09,
                                               0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00};
    n = mutate(first_ext(good_cert, good_cert_len), 0, critical_unknown, sizeof critical_unknown);
    CHECK(rejected(mutant_a, n, ALERT_UNSUPPORTED_CERTIFICATE));
    CHECK(grammar_ok(mutant_a, insert_unknown(mutant_a, good_cert, good_cert_len, 0x09)));

    // Extension count: the vector's 5 plus 3 unknowns reaches the
    // bound of 8 and parses; a 9th is over it.
    n = insert_unknown(mutant_a, good_cert, good_cert_len, 0x09);
    size_t n2 = insert_unknown(mutant_b, mutant_a, n, 0x10);
    n = insert_unknown(mutant_a, mutant_b, n2, 0x11);
    CHECK(grammar_ok(mutant_a, n));
    n2 = insert_unknown(mutant_b, mutant_a, n, 0x12);
    CHECK(rejected(mutant_b, n2, ALERT_UNSUPPORTED_CERTIFICATE));

    // One extension TLV at the size bound: 256 parses, 257 does not.
    CHECK(grammar_ok(mutant_a, insert_big(mutant_a, good_cert, good_cert_len, 256)));
    n = insert_big(mutant_a, good_cert, good_cert_len, 257);
    CHECK(rejected(mutant_a, n, ALERT_BAD_CERTIFICATE));

    // extnID content bound: an unknown non-critical OID of 16 content
    // bytes parses; 17 does not. Every byte stays under 0x80, so each
    // is one complete, minimal subidentifier.
    uint8_t oid_ext[25] = {0x30, 0x16, 0x06, 0x10};
    memset(oid_ext + 4, 0x2a, 16);
    memcpy(oid_ext + 20, (const uint8_t[]){0x04, 0x02, 0x30, 0x00}, 4);
    n = splice(mutant_a, good_cert, good_cert_len, first_ext(good_cert, good_cert_len), 0, oid_ext,
               24);
    CHECK(grammar_ok(mutant_a, n));
    oid_ext[1] = 0x17;
    oid_ext[3] = 0x11;
    memcpy(oid_ext + 21, (const uint8_t[]){0x04, 0x02, 0x30, 0x00}, 4);
    n = splice(mutant_a, good_cert, good_cert_len, first_ext(good_cert, good_cert_len), 0, oid_ext,
               25);
    CHECK(rejected(mutant_a, n, ALERT_BAD_CERTIFICATE));

    // A non-minimal extnID: 0x80 inserted at the start of keyUsage's
    // final subidentifier encodes the same OID a second way, which
    // X.690 §8.19 forbids and the decoder rejects as malformed.
    size_t ku_oid =
        nth_child(good_cert, good_cert_len, find_ext(good_cert, good_cert_len, oid_ku), 0);
    n = mutate(ku_oid, tlv_total(good_cert, good_cert_len, ku_oid),
               (const uint8_t[]){0x06, 0x04, 0x55, 0x1d, 0x80, 0x0f}, 6);
    CHECK(rejected(mutant_a, n, ALERT_BAD_CERTIFICATE));
}

// signatureValue: the certificate's third child, a BIT STRING whose
// bits fill whole bytes. Both builds run these; the shape rules sit
// in x509_read_bitstring, before any algorithm-specific code.
static void test_sigvalue(void) {
    size_t sig = nth_child(good_cert, good_cert_len, 0, 2);
    tlv_shape s;
    tlv_read(good_cert + sig, good_cert_len - sig, &s);

    // A nonzero unused-bits octet: malformed, seeded alert stands.
    size_t n = patch2(mutant_a, sig + s.header_len, 0x01, good_cert[sig + s.header_len + 1]);
    CHECK(rejected(mutant_a, n, ALERT_BAD_CERTIFICATE));

    // An empty signature: content is only the unused-bits octet.
    n = mutate(sig, s.header_len + s.content_len, (const uint8_t[]){0x03, 0x01, 0x00}, 3);
    CHECK(rejected(mutant_a, n, ALERT_BAD_CERTIFICATE));
}

int main(void) {
    memcpy(wrong_ca, ca_key, ca_key_len);
    wrong_ca[1] ^= 0x40; // still key-shaped: RSA stays odd with its top byte

    // The count cases assume the minted certificates' extension
    // counts: 5 on the leaf, 4 on the intermediate (BC, KU, SKI, AKI).
    CHECK(ext_count(good_cert, good_cert_len) == 5);
    CHECK(ext_count(chain_int, chain_int_len) == 4);

    test_accept();
    test_list();
    test_chain();
    test_chain_intermediate();
    test_outer_and_serial();
    test_sigalg_and_time();
    test_epoch_dates();
    test_epoch_grammar_unchanged();
    test_epoch_from_chain();
    test_spki();
    test_decoded_extensions();
    test_ext_shape();
    test_sigvalue();

    if (failures > 0) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)printf("x509strict_test: all checks passed\n");
    return 0;
}
