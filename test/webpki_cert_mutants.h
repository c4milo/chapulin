// Boundary mutants for test/webpki_cert_test.c: the corpus r2 leaf
// (P-256, six extensions) and its P-256 intermediate, each changed at
// one field by test/x509_mutate.h's splice, which re-encodes every
// enclosing length. Each rule gets its last accepted value and its first
// refused one where the rule has a boundary. This file holds the
// certificate parser's rules (webpki_cert.c) and the helpers both mutant
// sets use; test/webpki_ext_mutants.h holds the extension walk's.
// Included by that file alone, after its CHECK macro and its helpers.
#ifndef CH_TEST_WEBPKI_CERT_MUTANTS_H
#define CH_TEST_WEBPKI_CERT_MUTANTS_H

#include <stdint.h>
#include <string.h>

#include "buf.h"
#include "handshake_message.h"
#include "webpki.h"
#include "x509_mutate.h"

static const uint8_t *base_leaf;
static size_t base_leaf_len;
static const uint8_t *base_issuer;
static size_t base_issuer_len;
static uint8_t mutant[X509MUT_CAP];
static webpki_cert mutant_parsed;

// Parses cert under the arm and requires rc and the alert it leaves. Both
// mutant files call this, so each caller passes its own file and line.
static void expect_verdict(const uint8_t *cert, size_t n, int is_ca, int want_rc,
                           uint8_t want_alert, const char *file, int line) {
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    int rc = webpki_parse_certificate(cert, n, is_ca, &mutant_parsed, &alert);
    if (rc != want_rc || alert != want_alert) {
        (void)fprintf(stderr, "FAIL %s:%d: rc %d alert %u, want rc %d alert %u\n", file, line, rc,
                      alert, want_rc, want_alert);
        failures++;
        return;
    }
    if (rc == CH_OK) {
        check_accepted(&mutant_parsed, cert, n, is_ca);
    }
}
#define EXPECT_OK(cert, n, is_ca)                                                                  \
    expect_verdict(cert, n, is_ca, CH_OK, ALERT_BAD_CERTIFICATE, __FILE__, __LINE__)
#define EXPECT_BAD(cert, n, is_ca)                                                                 \
    expect_verdict(cert, n, is_ca, CH_EPROTO, ALERT_BAD_CERTIFICATE, __FILE__, __LINE__)
#define EXPECT_UNSUPPORTED(cert, n, is_ca)                                                         \
    expect_verdict(cert, n, is_ca, CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE, __FILE__, __LINE__)

// The certificate with TBSCertificate field index (x509_mutate.h's
// numbering) replaced by repl; the result is in mutant.
static size_t with_tbs_field(const uint8_t *cert, size_t n, size_t index, const uint8_t *repl,
                             size_t repl_len) {
    size_t off = tbs_field(cert, n, index);
    return splice(mutant, cert, n, off, tlv_total(cert, n, off), repl, repl_len);
}

// The certificate with the extension whose extnID is oid3 replaced by
// repl, or removed when repl_len is 0.
static size_t with_extension(const uint8_t *cert, size_t n, const uint8_t oid3[3],
                             const uint8_t *repl, size_t repl_len) {
    size_t off = find_ext(cert, n, oid3);
    return splice(mutant, cert, n, off, tlv_total(cert, n, off), repl, repl_len);
}

// The certificate with repl inserted before its first extension.
static size_t with_first_extension(const uint8_t *cert, size_t n, const uint8_t *repl,
                                   size_t repl_len) {
    return splice(mutant, cert, n, first_ext(cert, n), 0, repl, repl_len);
}

static const uint8_t oid_ku[3] = {0x55, 0x1d, 0x0f};
static const uint8_t oid_san[3] = {0x55, 0x1d, 0x11};
static const uint8_t oid_bc[3] = {0x55, 0x1d, 0x13};
static const uint8_t oid_eku[3] = {0x55, 0x1d, 0x25};

// RFC 5280 §4.1.2.2 at 20 value octets: 20 with the pad a top-bit-set
// value needs and 20 without a pad are accepted, 21 are refused.
static void test_serial_bound(void) {
    uint8_t serial[23] = {0x02, 0x15, 0x00, 0x80};
    memset(serial + 4, 0x11, 19);
    EXPECT_OK(mutant, with_tbs_field(base_leaf, base_leaf_len, 1, serial, 23), 0);
    serial[1] = 0x14;
    serial[2] = 0x7f;
    EXPECT_OK(mutant, with_tbs_field(base_leaf, base_leaf_len, 1, serial, 22), 0);
    serial[1] = 0x15;
    serial[2] = 0x01;
    serial[3] = 0x00;
    EXPECT_BAD(mutant, with_tbs_field(base_leaf, base_leaf_len, 1, serial, 23), 0);
}

// An unknown non-critical extension (2.5.29.9) whose whole TLV is total
// bytes, with long-form lengths on both its SEQUENCE and its OCTET STRING.
static size_t sized_extension(uint8_t *e, size_t total) {
    size_t content = total - 4;
    size_t filler = content - 9;
    static const uint8_t head[] = {0x30, 0x82, 0x00, 0x00, 0x06, 0x03, 0x55,
                                   0x1d, 0x09, 0x04, 0x82, 0x00, 0x00};
    memcpy(e, head, sizeof head);
    e[2] = (uint8_t)(content >> 8);
    e[3] = (uint8_t)content;
    e[11] = (uint8_t)(filler >> 8);
    e[12] = (uint8_t)filler;
    memset(e + sizeof head, 0x5a, filler);
    return total;
}

// The shortest pad extension sized_extension writes in canonical DER:
// both its SEQUENCE content and its OCTET STRING content need 256 bytes.
#define PAD_EXTENSION_MIN 269

// base_leaf rebuilt at exactly total bytes, the extra length carried by
// unknown non-critical extensions after its own six. Every header in
// the rebuilt certificate takes the four-byte form. Returns total.
static size_t padded_leaf(uint8_t *out, size_t total) {
    tlv_shape tbs;
    tlv_shape list;
    size_t tbs_off = nth_child(base_leaf, base_leaf_len, 0, 0);
    tlv_read(base_leaf + tbs_off, base_leaf_len - tbs_off, &tbs);
    size_t fields = tbs_off + tbs.header_len;
    size_t ext_field = tbs_field(base_leaf, base_leaf_len, 7);
    size_t list_off = nth_child(base_leaf, base_leaf_len, ext_field, 0);
    tlv_read(base_leaf + list_off, base_leaf_len - list_off, &list);
    size_t tail = tbs_off + tbs.header_len + tbs.content_len;
    size_t fields_len = ext_field - fields;
    size_t tail_len = base_leaf_len - tail;
    size_t pad_len = total - 16 - fields_len - list.content_len - tail_len;
    size_t list_len = list.content_len + pad_len;
    size_t tbs_len = fields_len + 4 + 4 + list_len;
    size_t at = put_header(out, 0x30, 4 + tbs_len + tail_len);
    at += put_header(out + at, 0x30, tbs_len);
    memcpy(out + at, base_leaf + fields, fields_len);
    at += fields_len;
    at += put_header(out + at, 0xa3, 4 + list_len);
    at += put_header(out + at, 0x30, list_len);
    memcpy(out + at, base_leaf + list_off + list.header_len, list.content_len);
    at += list.content_len;
    while (pad_len > 0) {
        size_t size = pad_len;
        if (size > CH_WEBPKI_EXT_TLV_MAX) {
            size = pad_len - CH_WEBPKI_EXT_TLV_MAX < PAD_EXTENSION_MIN ? pad_len - PAD_EXTENSION_MIN
                                                                       : CH_WEBPKI_EXT_TLV_MAX;
        }
        at += sized_extension(out + at, size);
        pad_len -= size;
    }
    memcpy(out + at, base_leaf + tail, tail_len);
    CHECK(at + tail_len == total);
    return total;
}

// CH_WEBPKI_CERT_MAX: a certificate of 3072 bytes is accepted, one of
// 3073 bytes refused, both in canonical DER and within every other rule.
static void test_certificate_size_bound(void) {
    static uint8_t big[CH_WEBPKI_CERT_MAX + 1];
    size_t n = padded_leaf(big, CH_WEBPKI_CERT_MAX);
    EXPECT_OK(big, n, 0);
    CHECK(ext_count(big, n) <= CH_WEBPKI_EXT_COUNT_MAX);
    n = padded_leaf(big, CH_WEBPKI_CERT_MAX + 1);
    EXPECT_BAD(big, n, 0);
}

// version 3 only; the two signature fields must be equal byte for byte.
static void test_version_and_sigalg(void) {
    static const uint8_t v2[] = {0xa0, 0x03, 0x02, 0x01, 0x01};
    EXPECT_BAD(mutant, with_tbs_field(base_leaf, base_leaf_len, 0, v2, sizeof v2), 0);
    static const uint8_t ecdsa_sha384[] = {0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
                                           0x48, 0xce, 0x3d, 0x04, 0x03, 0x03};
    static const uint8_t sha1_rsa[] = {0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
                                       0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00};
    size_t outer = nth_child(base_leaf, base_leaf_len, 0, 1);
    size_t outer_len = tlv_total(base_leaf, base_leaf_len, outer);
    size_t n = splice(mutant, base_leaf, base_leaf_len, outer, outer_len, ecdsa_sha384,
                      sizeof ecdsa_sha384);
    EXPECT_UNSUPPORTED(mutant, n, 0);
    n = splice(mutant, base_leaf, base_leaf_len, outer, outer_len, sha1_rsa, sizeof sha1_rsa);
    EXPECT_UNSUPPORTED(mutant, n, 0);
    EXPECT_UNSUPPORTED(
        mutant, with_tbs_field(base_leaf, base_leaf_len, 2, ecdsa_sha384, sizeof ecdsa_sha384), 0);
    // Both fields changed together: equal again, and a parse reads no signature.
    static uint8_t both[X509MUT_CAP];
    n = with_tbs_field(base_leaf, base_leaf_len, 2, ecdsa_sha384, sizeof ecdsa_sha384);
    memcpy(both, mutant, n);
    outer = nth_child(both, n, 0, 1);
    n = splice(mutant, both, n, outer, tlv_total(both, n, outer), ecdsa_sha384,
               sizeof ecdsa_sha384);
    EXPECT_OK(mutant, n, 0);
    CHECK(mutant_parsed.sigalg == WEBPKI_SIG_ECDSA_SHA384);
}

// Three of the four fields webpki.h's alert exception names: malformed
// DER in the TBS signature AlgorithmIdentifier, the SubjectPublicKeyInfo
// or the outer signatureAlgorithm reports ALERT_UNSUPPORTED_CERTIFICATE,
// the alert an unadmitted algorithm or key reports, because one reader
// answers one verdict for both. test_purposes covers the fourth,
// keyUsage.
static void test_alert_exception(void) {
    // ecdsa-with-SHA256 with its length in the two-octet form, which is
    // legal BER and not DER.
    static const uint8_t sigalg_long_form[] = {0x30, 0x81, 0x0a, 0x06, 0x08, 0x2a, 0x86,
                                               0x48, 0xce, 0x3d, 0x04, 0x03, 0x02};
    EXPECT_UNSUPPORTED(
        mutant,
        with_tbs_field(base_leaf, base_leaf_len, 2, sigalg_long_form, sizeof sigalg_long_form), 0);
    static uint8_t spki[256];
    size_t spki_off = tbs_field(base_leaf, base_leaf_len, 6);
    size_t spki_len = tlv_total(base_leaf, base_leaf_len, spki_off);
    // CHECK counts a failure and returns, so it cannot stand between a
    // length and the copy that trusts it: the copy would run anyway. The
    // guard is the if, and CHECK reports why the case was skipped.
    CHECK(spki_len <= sizeof spki);
    if (spki_len <= sizeof spki) {
        memcpy(spki, base_leaf + spki_off, spki_len);
        spki[0] = 0x31; // SET, where SubjectPublicKeyInfo is a SEQUENCE
        EXPECT_UNSUPPORTED(mutant, with_tbs_field(base_leaf, base_leaf_len, 6, spki, spki_len), 0);
    }
    // An outer signatureAlgorithm that is not a well-formed
    // AlgorithmIdentifier: an OBJECT IDENTIFIER with no content octets.
    static const uint8_t malformed_sigalg[] = {0x30, 0x02, 0x06, 0x00};
    size_t outer = nth_child(base_leaf, base_leaf_len, 0, 1);
    size_t n =
        splice(mutant, base_leaf, base_leaf_len, outer, tlv_total(base_leaf, base_leaf_len, outer),
               malformed_sigalg, sizeof malformed_sigalg);
    EXPECT_UNSUPPORTED(mutant, n, 0);
}

// issuerUniqueID and subjectUniqueID are refused; so are an empty and a
// missing extensions field, and a byte after any of the three levels.
static void test_structure(void) {
    size_t ext_field = tbs_field(base_leaf, base_leaf_len, 7);
    static const uint8_t issuer_uid[] = {0x81, 0x02, 0x00, 0xaa};
    static const uint8_t subject_uid[] = {0x82, 0x02, 0x00, 0xaa};
    EXPECT_UNSUPPORTED(mutant,
                       splice(mutant, base_leaf, base_leaf_len, ext_field, 0, issuer_uid, 4), 0);
    EXPECT_UNSUPPORTED(mutant,
                       splice(mutant, base_leaf, base_leaf_len, ext_field, 0, subject_uid, 4), 0);
    static const uint8_t empty_extensions[] = {0xa3, 0x02, 0x30, 0x00};
    EXPECT_BAD(mutant, with_tbs_field(base_leaf, base_leaf_len, 7, empty_extensions, 4), 0);
    EXPECT_BAD(mutant, with_tbs_field(base_leaf, base_leaf_len, 7, NULL, 0), 0);

    static uint8_t tail[X509MUT_CAP];
    size_t ext_len = tlv_total(base_leaf, base_leaf_len, ext_field);
    memcpy(tail, base_leaf + ext_field, ext_len);
    tail[ext_len] = 0x05;
    tail[ext_len + 1] = 0x00;
    EXPECT_BAD(mutant, with_tbs_field(base_leaf, base_leaf_len, 7, tail, ext_len + 2), 0);
    // The Extensions SEQUENCE fills the [3] wrapper: one more Extension
    // after the SEQUENCE but inside the wrapper is refused. That Extension
    // is well-formed and unknown to the walk, so only the length check
    // refuses it.
    static const uint8_t past_list[] = {0x30, 0x07, 0x06, 0x03, 0x55, 0x1d, 0x09, 0x04, 0x00};
    size_t list_off = nth_child(base_leaf, base_leaf_len, ext_field, 0);
    size_t list_len = tlv_total(base_leaf, base_leaf_len, list_off);
    size_t at = put_header(tail, 0xa3, list_len + sizeof past_list);
    memcpy(tail + at, base_leaf + list_off, list_len);
    at += list_len;
    memcpy(tail + at, past_list, sizeof past_list);
    at += sizeof past_list;
    EXPECT_BAD(mutant, with_tbs_field(base_leaf, base_leaf_len, 7, tail, at), 0);
    size_t sig = nth_child(base_leaf, base_leaf_len, 0, 2);
    size_t sig_len = tlv_total(base_leaf, base_leaf_len, sig);
    memcpy(tail, base_leaf + sig, sig_len);
    tail[sig_len] = 0x05;
    tail[sig_len + 1] = 0x00;
    EXPECT_BAD(mutant, splice(mutant, base_leaf, base_leaf_len, sig, sig_len, tail, sig_len + 2),
               0);
    static const uint8_t empty_signature[] = {0x03, 0x01, 0x00};
    EXPECT_BAD(mutant, splice(mutant, base_leaf, base_leaf_len, sig, sig_len, empty_signature, 3),
               0);
    memcpy(tail, base_leaf, base_leaf_len);
    tail[base_leaf_len] = 0x00;
    EXPECT_OK(tail, base_leaf_len, 0);
    EXPECT_BAD(tail, base_leaf_len + 1, 0);
    // The other half of that rule: a Certificate SEQUENCE that ends
    // before its own signature, which stays inside cert_len. Every
    // field still reads, so only the length equality at the outer
    // header refuses it.
    tlv_shape outer;
    tlv_read(base_leaf, base_leaf_len, &outer);
    size_t at_outer = put_header(tail, 0x30, outer.content_len - sig_len);
    memcpy(tail + at_outer, base_leaf + outer.header_len, outer.content_len);
    EXPECT_BAD(tail, at_outer + outer.content_len, 0);
}

// notBefore equal to notAfter is accepted; notBefore a year after notAfter
// is refused. The two Times fill the Validity exactly: 30 content octets
// are accepted, and the same two Times followed by one byte or by a third
// Time are refused.
static void test_validity_order(void) {
    uint8_t validity[47] = {0x30, 0x1e, 0x17, 0x0d};
    memcpy(validity + 4, "270101000000Z", 13);
    validity[17] = 0x17;
    validity[18] = 0x0d;
    memcpy(validity + 19, "270101000000Z", 13);
    EXPECT_OK(mutant, with_tbs_field(base_leaf, base_leaf_len, 4, validity, 32), 0);
    CHECK(mutant_parsed.not_before == UINT64_C(20270101000000));
    memcpy(validity + 19, "260101000000Z", 13);
    EXPECT_BAD(mutant, with_tbs_field(base_leaf, base_leaf_len, 4, validity, 32), 0);
    memcpy(validity + 19, "270101000000Z", 13);
    validity[1] = 0x1f;
    validity[32] = 0x00;
    EXPECT_BAD(mutant, with_tbs_field(base_leaf, base_leaf_len, 4, validity, 33), 0);
    validity[1] = 0x2d;
    validity[32] = 0x17;
    validity[33] = 0x0d;
    memcpy(validity + 34, "270101000000Z", 13);
    EXPECT_BAD(mutant, with_tbs_field(base_leaf, base_leaf_len, 4, validity, 47), 0);
}

static void test_mutants(void) {
    flight f;
    CHECK(read_flight(webpki_corpus_message_r2, sizeof webpki_corpus_message_r2, &f));
    base_leaf = f.cert[0];
    base_leaf_len = f.cert_len[0];
    base_issuer = f.cert[1];
    base_issuer_len = f.cert_len[1];
    EXPECT_OK(base_leaf, base_leaf_len, 0);
    // san is the subjectAltName extnValue's content: the GeneralNames TLV.
    size_t value =
        ext_child(base_leaf, base_leaf_len, find_ext(base_leaf, base_leaf_len, oid_san), 0x04);
    tlv_shape shape;
    tlv_read(base_leaf + value, base_leaf_len - value, &shape);
    CHECK(mutant_parsed.san == base_leaf + value + shape.header_len);
    CHECK(mutant_parsed.san_len == shape.content_len && mutant_parsed.san[0] == 0x30);
    EXPECT_OK(base_issuer, base_issuer_len, 1);
    EXPECT_UNSUPPORTED(base_leaf, base_leaf_len, 1);
    EXPECT_UNSUPPORTED(base_issuer, base_issuer_len, 0);
    test_serial_bound();
    test_certificate_size_bound();
    test_version_and_sigalg();
    test_alert_exception();
    test_structure();
    test_validity_order();
}

#endif
