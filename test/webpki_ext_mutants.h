// Boundary mutants for the extension walk (webpki_ext.c): the count and
// size caps, duplicates and unknown critical extensions, and the four
// extensions the walk judges. Each rule gets its last accepted value and
// its first refused one where the rule has a boundary.
//
// Included by test/webpki_cert_test.c after test/webpki_cert_mutants.h,
// whose base certificates, EXPECT_ macros, splice helpers and
// sized_extension it uses.
#ifndef CH_TEST_WEBPKI_EXT_MUTANTS_H
#define CH_TEST_WEBPKI_EXT_MUTANTS_H

#include <stdint.h>
#include <string.h>

#include "buf.h"
#include "handshake_message.h"
#include "webpki.h"
#include "x509_mutate.h"

// CH_WEBPKI_EXT_COUNT_MAX: 16 extensions are accepted, 17 refused.
static void test_extension_count_bound(void) {
    static uint8_t grow[X509MUT_CAP];
    size_t n = base_leaf_len;
    memcpy(grow, base_leaf, n);
    uint8_t arc = 0x40;
    while (ext_count(grow, n) < CH_WEBPKI_EXT_COUNT_MAX) {
        n = insert_unknown(mutant, grow, n, arc++);
        memcpy(grow, mutant, n);
    }
    EXPECT_OK(grow, n, 0);
    n = insert_unknown(mutant, grow, n, arc);
    CHECK(ext_count(mutant, n) == CH_WEBPKI_EXT_COUNT_MAX + 1);
    EXPECT_BAD(mutant, n, 0);
}

// CH_WEBPKI_EXT_TLV_MAX: a 1024-byte Extension is accepted, 1025 refused.
// insert_big's 258-byte one, over the ca profile's 256-byte cap, passes too.
static void test_extension_size_bound(void) {
    static uint8_t e[CH_WEBPKI_EXT_TLV_MAX + 1];
    EXPECT_OK(mutant, insert_big(mutant, base_leaf, base_leaf_len, 258), 0);
    size_t n = sized_extension(e, CH_WEBPKI_EXT_TLV_MAX);
    EXPECT_OK(mutant, with_first_extension(base_leaf, base_leaf_len, e, n), 0);
    n = sized_extension(e, CH_WEBPKI_EXT_TLV_MAX + 1);
    EXPECT_BAD(mutant, with_first_extension(base_leaf, base_leaf_len, e, n), 0);
}

// Duplicates of a recognized extension and unknown critical ones are
// refused; the same unknown extension non-critical is skipped.
static void test_duplicates_and_critical(void) {
    static uint8_t copy[CH_WEBPKI_EXT_TLV_MAX];
    size_t san = find_ext(base_leaf, base_leaf_len, oid_san);
    size_t san_len = tlv_total(base_leaf, base_leaf_len, san);
    memcpy(copy, base_leaf + san, san_len);
    EXPECT_UNSUPPORTED(mutant, with_first_extension(base_leaf, base_leaf_len, copy, san_len), 0);
    size_t ku = find_ext(base_issuer, base_issuer_len, oid_ku);
    size_t ku_len = tlv_total(base_issuer, base_issuer_len, ku);
    memcpy(copy, base_issuer + ku, ku_len);
    EXPECT_UNSUPPORTED(mutant, with_first_extension(base_issuer, base_issuer_len, copy, ku_len), 1);
    // nameConstraints (2.5.29.30) with an empty value, critical and not.
    static const uint8_t critical[] = {0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x1e,
                                       0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00};
    static const uint8_t plain[] = {0x30, 0x09, 0x06, 0x03, 0x55, 0x1d,
                                    0x1e, 0x04, 0x02, 0x30, 0x00};
    EXPECT_UNSUPPORTED(mutant, with_first_extension(base_issuer, base_issuer_len, critical, 14), 1);
    EXPECT_OK(mutant, with_first_extension(base_issuer, base_issuer_len, plain, 11), 1);
    EXPECT_UNSUPPORTED(mutant, with_first_extension(base_leaf, base_leaf_len, critical, 14), 0);
    // A second copy of an unknown non-critical extension is accepted:
    // webpki.h states that the duplicate rule covers the four the walk
    // judges and no others.
    static uint8_t twice[X509MUT_CAP];
    size_t n = with_first_extension(base_issuer, base_issuer_len, plain, 11);
    memcpy(twice, mutant, n);
    EXPECT_OK(mutant, with_first_extension(twice, n, plain, 11), 1);
    // An unknown non-critical extension is skipped with its extnValue
    // unread, but its extnID still goes through x509_read_extension's
    // 16-byte cap: 16 canonical octets are skipped, 17 refuse the
    // certificate.
    uint8_t wide_oid[25] = {0x30, 0x15, 0x06, 0x11, 0x2b};
    for (uint8_t i = 0; i < 16; i++) {
        wide_oid[5 + i] = (uint8_t)(i + 1);
    }
    wide_oid[21] = 0x04;
    wide_oid[22] = 0x00;
    EXPECT_BAD(mutant, with_first_extension(base_issuer, base_issuer_len, wide_oid, 23), 1);
    wide_oid[1] = 0x14;
    wide_oid[3] = 0x10;
    wide_oid[20] = 0x04;
    wide_oid[21] = 0x00;
    EXPECT_OK(mutant, with_first_extension(base_issuer, base_issuer_len, wide_oid, 22), 1);
}

// A basicConstraints extension with value, critical when asked.
static size_t basic_constraints(uint8_t *e, const uint8_t *value, size_t value_len, int critical) {
    static const uint8_t head[] = {0x30, 0x00, 0x06, 0x03, 0x55, 0x1d, 0x13};
    static const uint8_t true_flag[] = {0x01, 0x01, 0xff};
    size_t n = sizeof head;
    memcpy(e, head, n);
    if (critical) {
        memcpy(e + n, true_flag, sizeof true_flag);
        n += sizeof true_flag;
    }
    e[n++] = 0x04;
    e[n++] = (uint8_t)value_len;
    memcpy(e + n, value, value_len);
    n += value_len;
    e[1] = (uint8_t)(n - 2);
    return n;
}

// Replaces cert's basicConstraints with value and parses it under is_ca.
static void expect_basic_constraints(const uint8_t *cert, size_t cert_len, const uint8_t *value,
                                     size_t value_len, int critical, int is_ca, int want_rc,
                                     uint8_t want_alert, const char *file, int line) {
    uint8_t e[32];
    size_t n = basic_constraints(e, value, value_len, critical);
    expect_verdict(mutant, with_extension(cert, cert_len, oid_bc, e, n), is_ca, want_rc, want_alert,
                   file, line);
}
#define ISSUER_BC(value, critical, rc, alert)                                                      \
    expect_basic_constraints(base_issuer, base_issuer_len, value, sizeof(value), critical, 1, rc,  \
                             alert, __FILE__, __LINE__)
#define LEAF_BC(value, critical, rc, alert)                                                        \
    expect_basic_constraints(base_leaf, base_leaf_len, value, sizeof(value), critical, 0, rc,      \
                             alert, __FILE__, __LINE__)

static void test_basic_constraints(void) {
    static const uint8_t ca_path0[] = {0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00};
    static const uint8_t ca_only[] = {0x30, 0x03, 0x01, 0x01, 0xff};
    static const uint8_t path_negative[] = {0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0xff};
    static const uint8_t path_negative_wide[] = {0x30, 0x07, 0x01, 0x01, 0xff,
                                                 0x02, 0x02, 0x80, 0x00};
    static const uint8_t path_padded[] = {0x30, 0x07, 0x01, 0x01, 0xff, 0x02, 0x02, 0x00, 0x05};
    static const uint8_t path_128[] = {0x30, 0x07, 0x01, 0x01, 0xff, 0x02, 0x02, 0x00, 0x80};
    static const uint8_t path_32767[] = {0x30, 0x07, 0x01, 0x01, 0xff, 0x02, 0x02, 0x7f, 0xff};
    static const uint8_t path_3_octets[] = {0x30, 0x08, 0x01, 0x01, 0xff,
                                            0x02, 0x03, 0x00, 0x80, 0x00};
    static const uint8_t false_written[] = {0x30, 0x03, 0x01, 0x01, 0x00};
    static const uint8_t not_ca[] = {0x30, 0x00};
    static const uint8_t not_ca_path0[] = {0x30, 0x03, 0x02, 0x01, 0x00};
    static const uint8_t path_then_null[] = {0x30, 0x08, 0x01, 0x01, 0xff,
                                             0x02, 0x01, 0x00, 0x05, 0x00};
    // The SEQUENCE ends before the extnValue does, so the pathLenConstraint
    // sits outside it.
    static const uint8_t path_outside_seq[] = {0x30, 0x03, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00};
    ISSUER_BC(ca_path0, 1, CH_OK, ALERT_BAD_CERTIFICATE);
    CHECK(mutant_parsed.path_len == 0 && mutant_parsed.is_ca == 1);
    ISSUER_BC(ca_path0, 0, CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE);
    ISSUER_BC(ca_only, 1, CH_OK, ALERT_BAD_CERTIFICATE);
    CHECK(mutant_parsed.path_len == -1);
    ISSUER_BC(path_128, 1, CH_OK, ALERT_BAD_CERTIFICATE);
    CHECK(mutant_parsed.path_len == 128);
    ISSUER_BC(path_32767, 1, CH_OK, ALERT_BAD_CERTIFICATE);
    CHECK(mutant_parsed.path_len == 32767);
    ISSUER_BC(path_3_octets, 1, CH_EPROTO, ALERT_BAD_CERTIFICATE);
    ISSUER_BC(path_negative, 1, CH_EPROTO, ALERT_BAD_CERTIFICATE);
    ISSUER_BC(path_negative_wide, 1, CH_EPROTO, ALERT_BAD_CERTIFICATE);
    ISSUER_BC(path_padded, 1, CH_EPROTO, ALERT_BAD_CERTIFICATE);
    ISSUER_BC(path_outside_seq, 1, CH_EPROTO, ALERT_BAD_CERTIFICATE);
    ISSUER_BC(not_ca_path0, 1, CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE);
    ISSUER_BC(not_ca, 1, CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE);
    ISSUER_BC(path_then_null, 1, CH_EPROTO, ALERT_BAD_CERTIFICATE);
    LEAF_BC(false_written, 1, CH_EPROTO, ALERT_BAD_CERTIFICATE);
    LEAF_BC(not_ca, 0, CH_OK, ALERT_BAD_CERTIFICATE);
    LEAF_BC(not_ca_path0, 1, CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE);
    LEAF_BC(ca_only, 1, CH_EPROTO, ALERT_UNSUPPORTED_CERTIFICATE);
    // basicConstraints is optional on the leaf and required on an issuer.
    EXPECT_OK(mutant, with_extension(base_leaf, base_leaf_len, oid_bc, NULL, 0), 0);
    EXPECT_UNSUPPORTED(mutant, with_extension(base_issuer, base_issuer_len, oid_bc, NULL, 0), 1);
}

// keyUsage and extendedKeyUsage against each arm.
static void test_purposes(void) {
    // keyUsage, critical, over a two-octet BIT STRING value.
    uint8_t ku[] = {0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
                    0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0};
    EXPECT_OK(mutant, with_extension(base_leaf, base_leaf_len, oid_ku, ku, sizeof ku), 0);
    ku[15] = 0x20; // keyEncipherment alone
    EXPECT_UNSUPPORTED(mutant, with_extension(base_leaf, base_leaf_len, oid_ku, ku, sizeof ku), 0);
    ku[14] = 0x01;
    ku[15] = 0x02; // cRLSign alone
    EXPECT_UNSUPPORTED(mutant, with_extension(base_issuer, base_issuer_len, oid_ku, ku, sizeof ku),
                       1);
    ku[15] = 0x06; // keyCertSign and cRLSign
    EXPECT_OK(mutant, with_extension(base_issuer, base_issuer_len, oid_ku, ku, sizeof ku), 1);
    // Each arm needs its own bit: the other arm's bit alone does not do.
    ku[14] = 0x07;
    ku[15] = 0x80; // digitalSignature alone
    EXPECT_UNSUPPORTED(mutant, with_extension(base_issuer, base_issuer_len, oid_ku, ku, sizeof ku),
                       1);
    ku[14] = 0x02;
    ku[15] = 0x04; // keyCertSign alone
    EXPECT_UNSUPPORTED(mutant, with_extension(base_leaf, base_leaf_len, oid_ku, ku, sizeof ku), 0);
    // An OCTET STRING where the BIT STRING belongs is malformed DER, and
    // x509_read_keyusage answers the same 0 as a missing bit, so the alert
    // is the off-profile one: webpki.h's alert exception, keyUsage's half.
    static const uint8_t ku_not_bitstring[] = {0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
                                               0x01, 0xff, 0x04, 0x04, 0x04, 0x02, 0x07, 0x80};
    EXPECT_UNSUPPORTED(
        mutant,
        with_extension(base_leaf, base_leaf_len, oid_ku, ku_not_bitstring, sizeof ku_not_bitstring),
        0);
    EXPECT_UNSUPPORTED(mutant, with_extension(base_leaf, base_leaf_len, oid_ku, NULL, 0), 0);
    EXPECT_UNSUPPORTED(mutant, with_extension(base_issuer, base_issuer_len, oid_ku, NULL, 0), 1);

    // extendedKeyUsage over clientAuth then serverAuth, and variants.
    uint8_t eku[] = {0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x16, 0x30, 0x14,
                     0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06,
                     0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01};
    EXPECT_OK(mutant, with_extension(base_leaf, base_leaf_len, oid_eku, eku, sizeof eku), 0);
    eku[30] = 0x02; // clientAuth twice
    EXPECT_UNSUPPORTED(mutant, with_extension(base_leaf, base_leaf_len, oid_eku, eku, sizeof eku),
                       0);
    EXPECT_OK(mutant, with_extension(base_issuer, base_issuer_len, oid_eku, eku, sizeof eku), 1);
    eku[22] = 0x00; // the second OID zero bytes long, its content left as a stray
    EXPECT_BAD(mutant, with_extension(base_leaf, base_leaf_len, oid_eku, eku, sizeof eku), 0);
    // serverAuth, then an OBJECT IDENTIFIER with no content octets.
    static const uint8_t eku_zero_oid[] = {0x30, 0x15, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04,
                                           0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01,
                                           0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x00};
    EXPECT_BAD(mutant,
               with_extension(base_leaf, base_leaf_len, oid_eku, eku_zero_oid, sizeof eku_zero_oid),
               0);
    static const uint8_t eku_empty[] = {0x30, 0x09, 0x06, 0x03, 0x55, 0x1d,
                                        0x25, 0x04, 0x02, 0x30, 0x00};
    EXPECT_BAD(mutant,
               with_extension(base_leaf, base_leaf_len, oid_eku, eku_empty, sizeof eku_empty), 0);
    // The ExtKeyUsageSyntax SEQUENCE ends before the extnValue does, so
    // the second KeyPurposeId sits outside the list. It is well-formed, so
    // only the length check refuses it.
    static const uint8_t eku_past_list[] = {0x30, 0x18, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x11,
                                            0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
                                            0x07, 0x03, 0x01, 0x06, 0x03, 0x55, 0x1d, 0x25};
    EXPECT_BAD(
        mutant,
        with_extension(base_leaf, base_leaf_len, oid_eku, eku_past_list, sizeof eku_past_list), 0);
    // serverAuth beside a KeyPurposeId whose OBJECT IDENTIFIER is not
    // minimal: accepted, because only serverAuth is compared and no other
    // purpose is read, which webpki.h states.
    static const uint8_t eku_wide_oid[] = {0x30, 0x17, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x10,
                                           0x30, 0x0e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
                                           0x07, 0x03, 0x01, 0x06, 0x02, 0x80, 0x01};
    EXPECT_OK(mutant,
              with_extension(base_leaf, base_leaf_len, oid_eku, eku_wide_oid, sizeof eku_wide_oid),
              0);
    EXPECT_UNSUPPORTED(mutant, with_extension(base_leaf, base_leaf_len, oid_eku, NULL, 0), 0);
    EXPECT_UNSUPPORTED(mutant, with_extension(base_leaf, base_leaf_len, oid_san, NULL, 0), 0);
    // An empty GeneralNames is recorded and not judged here, which
    // webpki.h states: webpki_match_san refuses it as a name that does
    // not match.
    static const uint8_t san_empty[] = {0x30, 0x09, 0x06, 0x03, 0x55, 0x1d,
                                        0x11, 0x04, 0x02, 0x30, 0x00};
    EXPECT_OK(mutant,
              with_extension(base_leaf, base_leaf_len, oid_san, san_empty, sizeof san_empty), 0);
    CHECK(mutant_parsed.san_len == 2 && mutant_parsed.san[0] == 0x30);
    // subjectAltName is not required of an issuer, and not recorded when absent.
    EXPECT_OK(base_issuer, base_issuer_len, 1);
    CHECK(mutant_parsed.san == NULL && mutant_parsed.san_len == 0);
}

static void test_extension_mutants(void) {
    test_extension_count_bound();
    test_extension_size_bound();
    test_duplicates_and_critical();
    test_basic_constraints();
    test_purposes();
}

#endif
