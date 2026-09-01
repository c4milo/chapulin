// Provisioning differential: certificates the Lean spec mints, armoured
// by the driver, run through ch_pubkey_from_pem and through
// Spec.X509Ca.caKey?, held to the same verdict and the same key bytes.
//
// No certificate material is invented here. Every row starts from
// x509mint, so the bytes are the spec's own and a disagreement is a
// disagreement about the walk rather than about the fixture.
//
// The walk's grammar differs from the verifier's on purpose -- any
// pathLen, keyUsage optional, no extendedKeyUsage, signature framing
// read but never checked -- so these rows exist rather than reusing
// the x509parse ones. Included by diff_x509.h after x509_mutate.h.
#ifndef CH_DIFF_X509_CA_H
#define CH_DIFF_X509_CA_H

#include "pem.h"
#include "x509_ca.h"

// certd_mint returns a CertificateEntry: a 3-byte length, the
// certificate, then the empty per-entry extension block.
static size_t dca_unwrap(const uint8_t *entry, const uint8_t **cert) {
    *cert = entry + 3;
    return ((size_t)entry[0] << 16) | ((size_t)entry[1] << 8) | entry[2];
}

// One row: both sides see the same armour and must agree on the
// verdict, and on the bytes when they accept.
static void dca_row(const uint8_t *cert, size_t cert_len, size_t width, const char *eol) {
    static uint8_t pem[CH_PEM_MAX + 64];
    if (cert_len == 0 || cert_len > CH_X509_MAX) {
        return; // outside the domain both sides model
    }
    size_t pem_len = pem_armor(cert, cert_len, width, eol, pem);
    static uint8_t der[CH_X509_MAX];
    static uint8_t key[CH_X509_KEY_MAX];
    size_t key_len = 0;
    int rc = ch_pubkey_from_pem(pem, pem_len, der, key, &key_len);

    static char want[2 * CH_X509_KEY_MAX + 8];
    if (rc == CH_OK) {
        (void)memcpy(want, "ok ", 3);
        (void)hex_encode(want + 3, key, key_len);
    } else {
        (void)snprintf(want, sizeof want, "ERR pemcakey reject");
    }
    static char cmd[2 * (CH_PEM_MAX + 64) + 64];
    int head = snprintf(cmd, sizeof cmd, "pemcakey %s %d ", certd_build_alg, (int)CH_X509_MAX);
    (void)hex_encode(cmd + head, pem, pem_len);
    expect(cmd, want);
}

// The extension sets that decide the verdict, minted fresh each time.
static void dca_extension_rows(const char *leaf_hex) {
    // Two anchor shapes the walk accepts and two it does not: CA:TRUE
    // with pathLen 0, CA:TRUE with none, a leaf's keyUsage plus
    // extendedKeyUsage, and keyUsage alone. None carries
    // basicConstraints except the first two.
    // basicConstraints CA:TRUE plus keyUsage(digitalSignature): an
    // anchor whose own keyUsage forbids signing certificates. No other
    // set combines those, so nothing else isolates the keyCertSign rule.
    static const char *const ca_ku_no_certsign_hex =
        "300e0603551d0f0101ff04040302078030120603551d130101ff040830060101ff020100";
    // keyUsage(keyCertSign) and no basicConstraints at all. The other
    // two sets without basicConstraints carry keyUsage(digitalSignature),
    // so the keyCertSign rule rejects them first and nothing else
    // isolates "an anchor must assert CA:TRUE".
    static const char *const ku_certsign_no_bc_hex = "300e0603551d0f0101ff040403020204";
    const char *const exts[6] = {certd_int_exts_hex,   certd_int_exts_no_pathlen_hex,
                                 certd_exts_hex,       certd_exts_no_eku_hex,
                                 ca_ku_no_certsign_hex, ku_certsign_no_bc_hex};
    for (size_t i = 0; i < 6; i++) {
        static uint8_t entry[CERTD_CERT_MAX + 16];
        (void)certd_mint(certd_build_alg, certd_serial_hex, certd_name_hex, leaf_hex, exts[i],
                         entry);
        const uint8_t *cert = NULL;
        size_t cert_len = dca_unwrap(entry, &cert);
        for (size_t w = 0; w < sizeof pem_armor_widths / sizeof *pem_armor_widths; w++) {
            dca_row(cert, cert_len, pem_armor_widths[w], rng_below(2) != 0 ? "\r\n" : "\n");
        }
    }
}

// Randomized mutation of an anchor the walk accepts. Every enclosing
// DER length is re-encoded, so each mutant is a well-formed
// certificate that differs from a valid one in one place.
static void dca_mutation_rows(const char *leaf_hex) {
    static uint8_t entry[CERTD_CERT_MAX + 16];
    static uint8_t mut[X509MUT_CAP];
    (void)certd_mint(certd_build_alg, certd_serial_hex, certd_name_hex, leaf_hex,
                     certd_int_exts_hex, entry);
    const uint8_t *cert = NULL;
    size_t cert_len = dca_unwrap(entry, &cert);

    for (int i = 0; i < 210; i++) {
        (void)memcpy(mut, cert, cert_len);
        size_t len = cert_len;
        switch (rng_below(7)) {
        case 0: // one byte anywhere becomes any other byte
            mut[rng_below(cert_len)] = (uint8_t)(rng_next() >> 56);
            break;
        case 1: // truncated anywhere
            len = rng_below(cert_len);
            break;
        case 2: // one byte appended past the outer SEQUENCE
            mut[cert_len] = (uint8_t)(rng_next() >> 56);
            len = cert_len + 1;
            break;
        case 3: { // a TBS field replaced by a NULL, lengths re-encoded
            size_t which = rng_below(8);
            size_t off = tbs_field(cert, cert_len, which);
            static const uint8_t der_null[] = {0x05, 0x00};
            len = splice(mut, cert, cert_len, off, tlv_total(cert, cert_len, off), der_null,
                         sizeof der_null);
            break;
        }
        case 5: { // a trailing field inside the TBS, after the extensions
            size_t ext_off = tbs_field(cert, cert_len, 7);
            size_t ext_len = tlv_total(cert, cert_len, ext_off);
            static uint8_t grown[X509MUT_CAP];
            static const uint8_t der_null[] = {0x05, 0x00};
            (void)memcpy(grown, cert + ext_off, ext_len);
            (void)memcpy(grown + ext_len, der_null, sizeof der_null);
            len = splice(mut, cert, cert_len, ext_off, ext_len, grown,
                         ext_len + sizeof der_null);
            break;
        }
        case 6: // the outer SEQUENCE declaring less than it holds, every
                // byte still present: only the body_len check rejects it
            if (mut[1] == 0x82) {
                mut[2] = 0x01;
                mut[3] = 0x00;
            }
            break;
        default: { // an unknown extension, critical half the time
            static const uint8_t crit[] = {0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x63,
                                           0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00};
            if (rng_below(2) != 0) {
                len = splice(mut, cert, cert_len, first_ext(cert, cert_len), 0, crit, sizeof crit);
            } else {
                len = insert_unknown(mut, cert, cert_len, (uint8_t)(0x60 + rng_below(16)));
            }
            break;
        }
        }
        dca_row(mut, len, pem_armor_widths[rng_below(sizeof pem_armor_widths /
                                                     sizeof *pem_armor_widths)],
                rng_below(2) != 0 ? "\r\n" : "\n");
    }
}

// Only the build's own algorithm: ch_pubkey_from_pem reads one SPKI
// arm, so a row in the other arm would compare the C's rejection
// against the spec's acceptance and prove nothing about either.
// The signature BIT STRING's framing, as exact pairs. A review found
// the spec laxer than the C here -- accepting a nonzero unused-bits
// octet and a one-byte BIT STRING -- and the random byte-flip rows
// above reach that octet often enough to split the sides about once
// per eleven nightly runs. These rows pin the boundary every run.
static void dca_sig_framing_rows(const char *leaf_hex) {
    static uint8_t entry[CERTD_CERT_MAX + 16];
    static uint8_t mut[X509MUT_CAP];
    (void)certd_mint(certd_build_alg, certd_serial_hex, certd_name_hex, leaf_hex,
                     certd_int_exts_hex, entry);
    const uint8_t *cert = NULL;
    size_t cert_len = dca_unwrap(entry, &cert);
    size_t body = nth_child(cert, cert_len, 0, 0);
    (void)body;
    size_t sig = nth_child(cert, cert_len, 0, 2);
    tlv_shape sh;
    tlv_read(cert + sig, cert_len - sig, &sh);

    // A nonzero unused-bits octet: signature bits fill whole bytes.
    (void)memcpy(mut, cert, cert_len);
    mut[sig + sh.header_len] = 0x05;
    dca_row(mut, cert_len, 64, "\n");

    // A BIT STRING holding only the unused-bits octet: no signature.
    static const uint8_t sig_empty[] = {0x03, 0x01, 0x00};
    size_t n = splice(mut, cert, cert_len, sig, tlv_total(cert, cert_len, sig), sig_empty,
                      sizeof sig_empty);
    dca_row(mut, n, 64, "\n");

    // basicConstraints carrying an empty pathLenConstraint INTEGER
    // (30 05 01 01 ff 02 00). Both sides accept it -- the laxity
    // isCaTrue_iff states -- and no minted certificate or mutation
    // reaches a two-byte in-INTEGER edit, so the agreement was never
    // exercised until this row.
    static const uint8_t bc_empty_pathlen[] = {0x30, 0x11, 0x06, 0x03, 0x55, 0x1d, 0x13,
                                               0x01, 0x01, 0xff, 0x04, 0x07, 0x30, 0x05,
                                               0x01, 0x01, 0xff, 0x02, 0x00};
    static const uint8_t oid_bc_local[3] = {0x55, 0x1d, 0x13};
    size_t off = find_ext(cert, cert_len, oid_bc_local);
    n = splice(mut, cert, cert_len, off, tlv_total(cert, cert_len, off), bc_empty_pathlen,
               sizeof bc_empty_pathlen);
    dca_row(mut, n, 64, "\n");
}

static void diff_x509_ca(const char *leaf_hex) {
    dca_extension_rows(leaf_hex);
    dca_sig_framing_rows(leaf_hex);
    dca_mutation_rows(leaf_hex);
}

#endif
