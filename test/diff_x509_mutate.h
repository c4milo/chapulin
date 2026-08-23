// The mutation engine for the certificate differential: it decodes
// one minted certificate's spine, applies the design's mutation
// classes to every TLV on it (long-form length, non-minimal INTEGER
// pad, other-params AlgorithmIdentifier, present-DEFAULT, extra
// entries, keyUsage named-bit breaks, the extension size and count
// bounds), and sends one verdict row per mutant. Every mutant must be
// rejected on both sides, whichever check catches it first. The TLV
// carving comes from x509_mutate.h. Included by diff_x509.h after
// certd_wrap and certd_row, and before diff_x509_random.h, which walks
// the same spine; test/diff_test.c is the one translation unit.
#ifndef CH_DIFFX509MUTATE_H
#define CH_DIFFX509MUTATE_H

// The decoded spine: every TLV reachable through constructed
// containers, depth-first over an explicit range stack. Contents of
// primitive TLVs (times, OIDs, BIT STRINGs) are leaves.
static size_t certd_sites[192];
static size_t certd_site_count;

static void certd_collect(const uint8_t *cert, size_t cert_len) {
    size_t range_off[16];
    size_t range_end[16];
    size_t depth = 1;
    range_off[0] = 0;
    range_end[0] = cert_len;
    certd_site_count = 0;
    while (depth > 0) {
        size_t off = range_off[depth - 1];
        if (off >= range_end[depth - 1]) {
            depth--;
            continue;
        }
        tlv_shape s;
        tlv_read(cert + off, cert_len - off, &s);
        if (certd_site_count == sizeof certd_sites / sizeof certd_sites[0]) {
            mut_die("more spine TLVs than the site table holds");
        }
        certd_sites[certd_site_count++] = off;
        range_off[depth - 1] = off + s.header_len + s.content_len; // the next sibling
        if ((cert[off] & 0x20) != 0) {
            if (depth == sizeof range_off / sizeof range_off[0]) {
                mut_die("spine deeper than any certificate");
            }
            range_off[depth] = off + s.header_len;
            range_end[depth] = off + s.header_len + s.content_len;
            depth++;
        }
    }
}

// Re-encodes the TLV at off with its length one form longer than
// minimal, which X.690 §10.1 (DER) forbids; the splice re-encodes
// every enclosing length around the one extra octet.
static size_t certd_longform(uint8_t *out, const uint8_t *cert, size_t cert_len, size_t off) {
    static uint8_t repl[CERTD_CERT_MAX + 8];
    tlv_shape s;
    tlv_read(cert + off, cert_len - off, &s);
    size_t h = 0;
    repl[h++] = cert[off];
    if (s.header_len == 2) {
        repl[h++] = 0x81;
        repl[h++] = (uint8_t)s.content_len;
    } else if (s.header_len == 3) {
        repl[h++] = 0x82;
        repl[h++] = 0;
        repl[h++] = (uint8_t)s.content_len;
    } else {
        repl[h++] = 0x83;
        repl[h++] = 0;
        repl[h++] = (uint8_t)(s.content_len >> 8);
        repl[h++] = (uint8_t)s.content_len;
    }
    memcpy(repl + h, cert + off + s.header_len, s.content_len);
    return splice(out, cert, cert_len, off, s.header_len + s.content_len, repl, h + s.content_len);
}

// Grows the TLV at off by one 0x00 content byte: before the content
// for an INTEGER (the pad X.690 §8.3.2 bans) or after it for a
// container (which then no longer exact-fills).
static size_t certd_grow(uint8_t *out, const uint8_t *cert, size_t cert_len, size_t off,
                         int at_start) {
    static uint8_t repl[CERTD_CERT_MAX + 8];
    tlv_shape s;
    tlv_read(cert + off, cert_len - off, &s);
    size_t h = put_header(repl, cert[off], s.content_len + 1);
    memcpy(repl + h + (at_start ? 1U : 0U), cert + off + s.header_len, s.content_len);
    repl[at_start ? h : h + s.content_len] = 0;
    return splice(out, cert, cert_len, off, s.header_len + s.content_len, repl,
                  h + 1 + s.content_len);
}

// Encodes critical FALSE inside the extension at off. FALSE is the
// DEFAULT, which DER (X.690 §11.5) requires to stay absent.
static size_t certd_default_false(uint8_t *out, const uint8_t *cert, size_t cert_len, size_t off) {
    static uint8_t repl[CERTD_CERT_MAX + 8];
    static const uint8_t false_tlv[3] = {0x01, 0x01, 0x00};
    tlv_shape s;
    tlv_read(cert + off, cert_len - off, &s);
    size_t oid_total = tlv_total(cert, cert_len, off + s.header_len);
    size_t h = put_header(repl, 0x30, s.content_len + 3);
    memcpy(repl + h, cert + off + s.header_len, oid_total);
    memcpy(repl + h + oid_total, false_tlv, 3);
    memcpy(repl + h + oid_total + 3, cert + off + s.header_len + oid_total,
           s.content_len - oid_total);
    return splice(out, cert, cert_len, off, s.header_len + s.content_len, repl,
                  h + 3 + s.content_len);
}

// Wraps one mutated certificate and sends its verdict row; every
// mutant must be rejected on both sides.
static void certd_mutant_row(const char *alg, const char *ca_hex, const uint8_t *ca_key,
                             size_t ca_len, const uint8_t *mut, size_t mut_len) {
    static uint8_t list[CERTD_CERT_MAX + 16];
    size_t n = certd_wrap(list, mut, mut_len);
    certd_row(alg, ca_hex, ca_key, ca_len, list, n, NULL);
}

// Walks the decoded spine and sends one row per mutant: the long-form
// length everywhere, the grow for INTEGERs and containers, and the
// other-params swap at both pinned-sigalg sites.
static void certd_spine_rows(const char *alg, const char *ca_hex, const uint8_t *ca_key,
                             size_t ca_len, const uint8_t *cert, size_t cert_len) {
    static uint8_t mut[CERTD_CERT_MAX + 8];
    static uint8_t pinned[80];
    static uint8_t other[80];
    const int is_rsa = strcmp(alg, "rsa") == 0;
    const char *pinned_hex = is_rsa ? certd_sigalg_rsa_hex : certd_sigalg_p256_hex;
    const char *other_hex = is_rsa ? certd_sigalg_rsa_other_hex : certd_sigalg_p256_other_hex;
    size_t pinned_len = strlen(pinned_hex) / 2;
    size_t other_len = strlen(other_hex) / 2;
    if (!hex_decode(pinned, pinned_hex, pinned_len) || !hex_decode(other, other_hex, other_len)) {
        die("cert: malformed sigalg constant");
    }
    certd_collect(cert, cert_len);
    size_t sigalg_hits = 0;
    for (size_t i = 0; i < certd_site_count; i++) {
        size_t off = certd_sites[i];
        size_t n = certd_longform(mut, cert, cert_len, off);
        certd_mutant_row(alg, ca_hex, ca_key, ca_len, mut, n);
        if (cert[off] == 0x02 || (cert[off] & 0x20) != 0) {
            n = certd_grow(mut, cert, cert_len, off, cert[off] == 0x02);
            certd_mutant_row(alg, ca_hex, ca_key, ca_len, mut, n);
        }
        if (tlv_total(cert, cert_len, off) == pinned_len &&
            memcmp(cert + off, pinned, pinned_len) == 0) {
            sigalg_hits++;
            n = splice(mut, cert, cert_len, off, pinned_len, other, other_len);
            certd_mutant_row(alg, ca_hex, ca_key, ca_len, mut, n);
        }
    }
    if (sigalg_hits != 2) {
        mut_die("pinned signature algorithm not found in both places");
    }
}

// Grows the extension list to the count bound and sends the exact
// boundary pair: at the bound the CA signature rejects, one past it
// the bound itself does.
static void certd_count_bound_rows(const char *alg, const char *ca_hex, const uint8_t *ca_key,
                                   size_t ca_len, const uint8_t *cert, size_t cert_len) {
    static uint8_t grow[CERTD_CERT_MAX + 8];
    static uint8_t grow_next[CERTD_CERT_MAX + 8];
    memcpy(grow, cert, cert_len);
    size_t grow_len = cert_len;
    for (size_t count = 2; count < CH_X509_EXT_COUNT_MAX + 1U; count++) {
        grow_len = insert_unknown(grow_next, grow, grow_len, (uint8_t)(0x3e + count));
        memcpy(grow, grow_next, grow_len);
        if (count + 1 >= CH_X509_EXT_COUNT_MAX) {
            certd_mutant_row(alg, ca_hex, ca_key, ca_len, grow, grow_len);
        }
    }
    if (ext_count(grow, grow_len) != CH_X509_EXT_COUNT_MAX + 1U) {
        mut_die("extension growth drifted off the count bound");
    }
}

// Walks the spine and sends every mutant's verdict row: the whole
// point is that the C parser and the spec reject each one for the
// same input, whichever check catches it first.
static void certd_mutants(const char *alg, const char *ca_hex, const uint8_t *ca_key, size_t ca_len,
                          const uint8_t *cert, size_t cert_len) {
    static uint8_t mut[CERTD_CERT_MAX + 8];
    certd_spine_rows(alg, ca_hex, ca_key, ca_len, cert, cert_len);
    // present-DEFAULT on the non-critical EKU extension.
    size_t eku = find_ext(cert, cert_len, (const uint8_t[]){0x55, 0x1d, 0x25});
    size_t n = certd_default_false(mut, cert, cert_len, eku);
    certd_mutant_row(alg, ca_hex, ca_key, ca_len, mut, n);
    // keyUsage named-bit breaks over 03 02 07 80: an unused-bit count
    // off the lowest set bit, then a set padding bit.
    size_t ku = find_ext(cert, cert_len, (const uint8_t[]){0x55, 0x1d, 0x0f});
    size_t kuval = ext_child(cert, cert_len, ku, 0x04);
    if (memcmp(cert + kuval, (const uint8_t[]){0x04, 0x04, 0x03, 0x02, 0x07, 0x80}, 6) != 0) {
        mut_die("keyUsage value is not the minted encoding");
    }
    memcpy(mut, cert, cert_len);
    mut[kuval + 4] = 0x06;
    certd_mutant_row(alg, ca_hex, ca_key, ca_len, mut, cert_len);
    mut[kuval + 4] = 0x07;
    mut[kuval + 5] = 0xc0;
    certd_mutant_row(alg, ca_hex, ca_key, ca_len, mut, cert_len);
    // An unknown non-critical extension stays inside the grammar, so
    // the rejection here is the CA signature's: the TBS bytes moved.
    n = insert_unknown(mut, cert, cert_len, 0x09);
    certd_mutant_row(alg, ca_hex, ca_key, ca_len, mut, n);
    // The extension TLV size bound, as an exact pair: the largest
    // admissible TLV still rejects on the signature; one more byte
    // rejects on the bound itself.
    n = insert_big(mut, cert, cert_len, CH_X509_EXT_TLV_MAX);
    certd_mutant_row(alg, ca_hex, ca_key, ca_len, mut, n);
    n = insert_big(mut, cert, cert_len, CH_X509_EXT_TLV_MAX + 1);
    certd_mutant_row(alg, ca_hex, ca_key, ca_len, mut, n);
    // The extension count bound: growing to exactly
    // CH_X509_EXT_COUNT_MAX rejects on the signature, one more on the
    // bound.
    certd_count_bound_rows(alg, ca_hex, ca_key, ca_len, cert, cert_len);
}

#endif
