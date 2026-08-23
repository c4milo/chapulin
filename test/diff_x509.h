// Certificate differential section: the Lean spec mints CA-signed
// leaves (x509mint) that the C parser must accept and extract the
// same key from; the driver then walks every TLV on the minted
// certificate's decoded spine, applies the design's mutation classes
// (long-form length, non-minimal INTEGER, other-params
// AlgorithmIdentifier, present-DEFAULT, trailing bytes, truncation,
// extra entries, keyUsage named-bit breaks), and holds C and spec to
// the same verdict (x509parse) over the same CertificateEntry-list
// bytes. An accept verdict is "ok <key> <epoch>": the leaf notBefore's
// epoch number in decimal when it is epoch-shaped, the single
// character "-" otherwise. This file holds the fixed mint material,
// the mint and verdict-row helpers every row family shares, and the
// per-algorithm pass that calls them. The families live in siblings:
// diff_x509_mutate.h carries the mutation classes, diff_x509_epoch.h the
// epoch boundary rows, and diff_x509_chain.h the two-entry chain rows.
// The RSA CA and leaf keys come from diff_rsa.h and the TLV carving
// from x509_mutate.h, so include this after diff_driver.h and diff_rsa.h;
// test/diff_test.c is the one translation unit.
#ifndef CH_DIFF_X509_H
#define CH_DIFF_X509_H

#ifdef __has_include
#if __has_include("x509.h")
#include "cfg.h"
#include "hsmsg.h"
#include "x509.h"

#include "x509_mutate.h"
#define DIFF_HAVE_CERT 1
#endif
#endif

#ifdef DIFF_HAVE_CERT

#ifdef CH_PIN_ECDSA
static const char *const certd_build_alg = "p256";
#else
static const char *const certd_build_alg = "rsa";
#endif

// P-256 CA private scalar and signing nonce (the RFC 6979 §A.2.5 test
// key), and an unrelated scalar whose public point is the leaf key.
static const char *const certd_p256_ca_d_hex =
    "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
static const char *const certd_p256_ca_k_hex =
    "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60";
static const char *const certd_p256_leaf_d_hex =
    "1b8e05f5ee0f8b25101f13b6dc3d514cbbbf6bc7e2b1c9f2f6a2e15c7a3d4e51";

// Fixed mint fields: PSS salt, serial value, an opaque Name content
// used for issuer and subject, one UTCTime plus one GeneralizedTime,
// and the profile's required extensions (keyUsage digitalSignature
// critical, EKU serverAuth).
static const char *const certd_salt_hex =
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
static const char *const certd_serial_hex = "2a";
static const char *const certd_name_hex = "310c300a06035504030c03636861";
static const char *const certd_validity_hex =
    "170d3235303130313030303030305a180f32303335303130313030303030305a";
// certd_validity_hex's notAfter TLV alone (GeneralizedTime
// 20350101000000Z); the epoch rows pair it with their own notBefore.
static const char *const certd_not_after_hex = "180f32303335303130313030303030305a";
static const char *const certd_exts_hex =
    "300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070301";
static const char *const certd_exts_no_eku_hex = "300e0603551d0f0101ff040403020780";
static const char *const certd_exts_eku_only_hex = "30130603551d25040c300a06082b06010505070301";
// The required pair plus one extension whose extnID breaks X.690
// §8.19.2: subidentifier 37 padded to 0x80 0x25, then a final
// subidentifier left incomplete (0xa5). Each certificate is genuinely
// CA-signed, so the extnID rule alone rejects it — without the rule
// the extension would read as unknown non-critical and the leaf would
// pass.
static const char *const certd_exts_oid_pad_hex =
    "300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070301"
    "30140604551d8025040c300a06082b06010505070301";
static const char *const certd_exts_oid_cut_hex =
    "300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070301"
    "30130603551da5040c300a06082b06010505070301";

// Largest CertificateEntry list a chain row builds: two certificates
// plus framing, with room for a third-entry mutant.
// The largest certificate the spec ever mints (an RSA-3072 leaf or
// intermediate), independent of the build's own CH_X509_MAX: in the
// ECDSA build the RSA rows still mint and run spec-side, and their
// material must fit the driver's buffers.
#define CERTD_CERT_MAX CH_X509_DEFAULT_MAX_RSA
#define CERTD_LIST_MAX (3 * CERTD_CERT_MAX + 48)

// The pinned signature AlgorithmIdentifier per algorithm and the
// other-params variant the profile rejects: RFC 4055 §3.1 also allows
// the RSA-PSS inner SHA-256 identifiers with absent parameters, and
// appending a NULL to ecdsa-with-SHA256 (RFC 5758 §3.2 wants it
// absent) is the ECDSA counterpart.
static const char *const certd_sigalg_rsa_hex =
    "304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f7"
    "0d010108300d06096086480165030402010500a203020120";
static const char *const certd_sigalg_rsa_other_hex =
    "303d06092a864886f70d01010a3030a00d300b0609608648016503040201a11a301806092a864886f70d01"
    "0108300b0609608648016503040201a203020120";
static const char *const certd_sigalg_p256_hex = "300a06082a8648ce3d040302";
static const char *const certd_sigalg_p256_other_hex = "300c06082a8648ce3d0403020500";

static long certd_rows;

// The epoch column every current mint produces: certd_validity_hex's
// notBefore is UTCTime 250101000000Z, epoch number 25*336 = 8400.
// The epoch rows point this at their own column around each call.
static const char *certd_epoch_want = "8400";

// Wraps one certificate as a CertificateEntry list: u24 length, the
// bytes, empty (u16 0) per-entry extensions.
static size_t certd_wrap(uint8_t *list, const uint8_t *cert, size_t cert_len) {
    return put_entry(list, cert, cert_len);
}

// The C parser's own verdict on one list, rendered as the oracle line
// the spec must reproduce. Every mismatch against what the row
// promised — an accepted mutant, another key, another epoch — dies
// here, where the C side is the one under test.
static void certd_c_verdict(const uint8_t *list, size_t list_len, const uint8_t *ca_key,
                            size_t ca_len, const char *leaf_hex, char *want, size_t want_cap) {
    x509_leaf_info info;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    int rc = x509_verify_leaf(list, list_len, ca_key, ca_len, NULL, 0, &info, &alert);
    if (rc != CH_OK) {
        // The C answer is the expectation in its own build, so a row
        // that predicted an accept still holds the spec to this
        // reject; the strictness suite owns accept/reject policy.
        (void)snprintf(want, want_cap, "ERR x509 reject");
        return;
    }
    if (leaf_hex == NULL) {
        die("cert: the C parser accepted a mutant");
    }
    static char key_hex[2 * 384 + 1];
    (void)hex_encode(key_hex, info.key, info.key_len);
    if (strcmp(key_hex, leaf_hex) != 0) {
        die("cert: the C parser extracted a different key");
    }
    char epoch_column[16] = "-";
    if (info.epoch_ok) {
        (void)snprintf(epoch_column, sizeof epoch_column, "%u", (unsigned)info.epoch);
    }
    if (strcmp(epoch_column, certd_epoch_want) != 0) {
        die("cert: the C parser extracted a different epoch");
    }
    (void)snprintf(want, want_cap, "ok %s %s", leaf_hex, epoch_column);
}

// One verdict row over the same list bytes. When the build's PIN
// algorithm matches, the C parser's own answer is the expectation and
// the spec must reproduce it; for the other algorithm the spec still
// answers, against the row's predicted verdict. leaf_hex names the key
// an accept must extract; NULL marks a mutant no parser may accept.
static void certd_row(const char *alg, const char *ca_hex, const uint8_t *ca_key, size_t ca_len,
                      const uint8_t *list, size_t list_len, const char *leaf_hex) {
    static char list_hex[2 * CERTD_LIST_MAX + 1];
    static char cmd[2 * CERTD_LIST_MAX + 1024];
    static char want[2 * 384 + 16];
    (void)hex_encode(list_hex, list, list_len);
    (void)snprintf(cmd, sizeof cmd, "x509parse %s %s %s", alg, ca_hex, list_hex);
    certd_rows++;
    if (strcmp(alg, certd_build_alg) == 0) {
        certd_c_verdict(list, list_len, ca_key, ca_len, leaf_hex, want, sizeof want);
        expect(cmd, want);
        return;
    }
    if (leaf_hex != NULL) {
        (void)snprintf(want, sizeof want, "ok %s %s", leaf_hex, certd_epoch_want);
        expect(cmd, want);
    } else {
        expect(cmd, "ERR x509 reject");
    }
}

// Mints one leaf through the spec; the driver supplies every field,
// serial value, validity, and subject content included. Returns the
// CertificateEntry-list bytes.
static size_t certd_mint_dated(const char *alg, const char *serial_hex, const char *validity_hex,
                               const char *subject_hex, const char *leaf_hex, const char *exts_hex,
                               uint8_t *list) {
    static char cmd[8192];
    static char list_hex[2 * (CERTD_CERT_MAX + 16) + 1];
    if (strcmp(alg, "rsa") == 0) {
        (void)snprintf(cmd, sizeof cmd, "x509mint rsa %s %s %s %s %s %s %s %s %s", diff_rsa_n2048,
                       diff_rsa_d2048, certd_salt_hex, serial_hex, certd_name_hex, validity_hex,
                       subject_hex, leaf_hex, exts_hex);
    } else {
        (void)snprintf(cmd, sizeof cmd, "x509mint p256 %s %s %s %s %s %s %s %s",
                       certd_p256_ca_d_hex, certd_p256_ca_k_hex, serial_hex, certd_name_hex,
                       validity_hex, subject_hex, leaf_hex, exts_hex);
    }
    query(cmd, list_hex, sizeof list_hex);
    size_t n = strlen(list_hex);
    if (n % 2 != 0 || n / 2 < 8 || n / 2 > CERTD_CERT_MAX + 8 ||
        !hex_decode(list, list_hex, n / 2)) {
        die("x509mint: malformed spec response");
    }
    return n / 2;
}

// The fixed-validity mint every non-epoch row shares.
static size_t certd_mint(const char *alg, const char *serial_hex, const char *subject_hex,
                         const char *leaf_hex, const char *exts_hex, uint8_t *list) {
    return certd_mint_dated(alg, serial_hex, certd_validity_hex, subject_hex, leaf_hex, exts_hex,
                            list);
}

#include "diff_x509_bounds.h"
#include "diff_x509_chain.h"
#include "diff_x509_epoch.h"
#include "diff_x509_mutate.h"
#include "diff_x509_random.h"
#include "diff_x509_signed.h"

// One algorithm's pass: mint, accept, mutate, and the wrong-CA and
// missing-EKU rejects. wrong_ca_hex must be a well-formed key of the
// same algorithm that did not sign the leaf.
static void diff_x509_alg(const char *alg, const char *ca_hex, const char *leaf_hex,
                          const char *wrong_ca_hex) {
    static uint8_t ca_key[384];
    static uint8_t wrong_ca[384];
    static uint8_t list[CERTD_CERT_MAX + 16];
    static uint8_t cert[CERTD_CERT_MAX + 8];
    size_t ca_len = strlen(ca_hex) / 2;
    size_t wrong_len = strlen(wrong_ca_hex) / 2;
    if (ca_len > sizeof ca_key || !hex_decode(ca_key, ca_hex, ca_len) ||
        wrong_len > sizeof wrong_ca || !hex_decode(wrong_ca, wrong_ca_hex, wrong_len)) {
        die("cert: malformed CA key constant");
    }
    size_t list_len =
        certd_mint(alg, certd_serial_hex, certd_name_hex, leaf_hex, certd_exts_hex, list);
    size_t cert_len = list_len - 5;
    if (list_len < 8 || list[list_len - 2] != 0 || list[list_len - 1] != 0) {
        die("x509mint: malformed list framing");
    }
    memcpy(cert, list + 3, cert_len);
    // The accept row, and the same leaf against a CA that never
    // signed it.
    certd_row(alg, ca_hex, ca_key, ca_len, list, list_len, leaf_hex);
    certd_row(alg, wrong_ca_hex, wrong_ca, wrong_len, list, list_len, NULL);
    if (strcmp(alg, certd_build_alg) == 0) {
        // C-only slot checks: slot B catches what slot A missed, and a
        // both-slots miss names the CA in its alert.
        certd_slot_checks(alg, list, list_len, wrong_ca, wrong_len, ca_key, ca_len,
                          "cert: slot B did not verify the leaf",
                          "cert: wrong CA must fail as unknown_ca");
    }
    certd_mutants(alg, ca_hex, ca_key, ca_len, cert, cert_len);
    certd_list_mutants(alg, ca_hex, ca_key, ca_len, cert, cert_len);
    certd_boundary_rows(alg, ca_hex, ca_key, ca_len, leaf_hex);
    certd_epoch_rows(alg, ca_hex, ca_key, ca_len, leaf_hex);
    // A leaf without the EKU extension never authenticates a server.
    list_len =
        certd_mint(alg, certd_serial_hex, certd_name_hex, leaf_hex, certd_exts_no_eku_hex, list);
    certd_row(alg, ca_hex, ca_key, ca_len, list, list_len, NULL);
    certd_alert(alg, ca_key, ca_len, list, list_len, CH_EPROTO, ALERT_BAD_CERTIFICATE,
                ALERT_UNSUPPORTED_CERTIFICATE,
                "cert: missing EKU must fail as unsupported_certificate");
    // The converse: a leaf with EKU alone never binds keyUsage.
    list_len =
        certd_mint(alg, certd_serial_hex, certd_name_hex, leaf_hex, certd_exts_eku_only_hex, list);
    certd_row(alg, ca_hex, ca_key, ca_len, list, list_len, NULL);
    certd_alert(alg, ca_key, ca_len, list, list_len, CH_EPROTO, ALERT_BAD_CERTIFICATE,
                ALERT_UNSUPPORTED_CERTIFICATE,
                "cert: missing keyUsage must fail as unsupported_certificate");
    // extnID subidentifier minimality (X.690 §8.19.2): a padded
    // subidentifier, then a truncated final one — each genuinely
    // CA-signed so the extnID rule alone rejects.
    list_len =
        certd_mint(alg, certd_serial_hex, certd_name_hex, leaf_hex, certd_exts_oid_pad_hex, list);
    certd_row(alg, ca_hex, ca_key, ca_len, list, list_len, NULL);
    list_len =
        certd_mint(alg, certd_serial_hex, certd_name_hex, leaf_hex, certd_exts_oid_cut_hex, list);
    certd_row(alg, ca_hex, ca_key, ca_len, list, list_len, NULL);
    // The certificate size cap, exact per algorithm.
    certd_cap_rows(alg, ca_hex, ca_key, ca_len, leaf_hex);
}

static void diff_x509(void) {
    static char ca_pub_hex[256];
    static char leaf_pub_hex[256];
    char cmd[128];
    (void)snprintf(cmd, sizeof cmd, "p256_pub %s", certd_p256_ca_d_hex);
    query(cmd, ca_pub_hex, sizeof ca_pub_hex);
    (void)snprintf(cmd, sizeof cmd, "p256_pub %s", certd_p256_leaf_d_hex);
    query(cmd, leaf_pub_hex, sizeof leaf_pub_hex);
    if (strlen(ca_pub_hex) != 128 || strlen(leaf_pub_hex) != 128) {
        die("p256_pub: malformed spec response");
    }
    // RSA: 2048-bit CA, 3072-bit leaf modulus doubling as the wrong
    // CA. P-256: the leaf's own point is the wrong CA — on the curve,
    // never the signer.
    diff_x509_alg("rsa", diff_rsa_n2048, diff_rsa_n3072, diff_rsa_n3072);
    diff_x509_alg("p256", ca_pub_hex, leaf_pub_hex, leaf_pub_hex);
    // Chains: RSA puts the 3072-bit key in the middle — its modulus
    // is also the wrong pin, so pinning the intermediate itself must
    // not accept the chain — and the CA's own modulus as the leaf key.
    diff_x509_chain("rsa", diff_rsa_n2048, diff_rsa_n2048, diff_rsa_n3072);
    diff_x509_chain("p256", ca_pub_hex, leaf_pub_hex, leaf_pub_hex);
    // Randomized rows last: they consume the PRNG, so appending them
    // leaves every earlier section's stream untouched.
    certd_rand_pass("rsa", diff_rsa_n2048, diff_rsa_n3072);
    certd_rand_pass("p256", ca_pub_hex, leaf_pub_hex);
    (void)printf("diff: x509: %ld verdict rows (%ld randomized x%lu), C == spec\n", certd_rows,
                 certd_rand_rows, certd_rand_multiplier());
}

#else // !DIFF_HAVE_CERT

static void diff_x509(void) {
    (void)fprintf(stderr, "diff: x509: skipped, cert.h not present\n");
}

#endif

#endif
