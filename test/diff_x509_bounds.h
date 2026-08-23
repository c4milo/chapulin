// Boundary and cap rows for the certificate differential: the exact
// last-valid/first-invalid pairs for serials, extension sizes and
// counts, and the per-algorithm certificate cap, each freshly signed
// by the spec. Included by diff_x509.h after the mint helpers, the
// session_tests.h pattern; not a standalone translation unit.

// Accept-side boundary pairs, each freshly signed by the spec: the
// last valid serial, extension TLV size, and extension count parse on
// both sides, and the first invalid one fails on both.
static void certd_boundary_rows(const char *alg, const char *ca_hex, const uint8_t *ca_key,
                                size_t ca_len, const char *leaf_hex) {
    static uint8_t list[CERTD_CERT_MAX + 16];
    static char exts_hex[2 * 768 + 1];
    static uint8_t ext[CH_X509_EXT_TLV_MAX + 8];
    // Serial value bound (RFC 5280 §4.1.2.2): content 21 is the 0x00
    // pad plus a 20-byte top-bit-set value. A 21-byte value and a
    // 22-byte content are both over it.
    static const char *const serials[3] = {
        "00ff112233445566778899aabbccddeeff00112233",
        "7f112233445566778899aabbccddeeff0011223344",
        "00ff112233445566778899aabbccddeeff0011223344",
    };
    size_t n;
    for (size_t i = 0; i < 3; i++) {
        n = certd_mint(alg, serials[i], certd_name_hex, leaf_hex, certd_exts_hex, list);
        certd_row(alg, ca_hex, ca_key, ca_len, list, n, i == 0 ? leaf_hex : NULL);
    }
    // Extension TLV size bound: one unknown non-critical extension of
    // exactly CH_X509_EXT_TLV_MAX bytes passes; one more byte fails.
    for (size_t total = CH_X509_EXT_TLV_MAX; total <= CH_X509_EXT_TLV_MAX + 1U; total++) {
        size_t content = total - 3;
        size_t filler = content - 8;
        memcpy(ext,
               (const uint8_t[]){0x30, 0x81, 0x00, 0x06, 0x03, 0x55, 0x1d, 0x09, 0x04, 0x81, 0x00},
               11);
        ext[2] = (uint8_t)content;
        ext[10] = (uint8_t)filler;
        memset(ext + 11, 0x5a, filler);
        size_t w = strlen(certd_exts_hex);
        memcpy(exts_hex, certd_exts_hex, w);
        (void)hex_encode(exts_hex + w, ext, total);
        n = certd_mint(alg, certd_serial_hex, certd_name_hex, leaf_hex, exts_hex, list);
        certd_row(alg, ca_hex, ca_key, ca_len, list, n,
                  total == CH_X509_EXT_TLV_MAX ? leaf_hex : NULL);
    }
    // Extension count bound: the required pair plus unknowns up to
    // CH_X509_EXT_COUNT_MAX in all passes; one more fails.
    for (size_t extra = CH_X509_EXT_COUNT_MAX - 2; extra <= CH_X509_EXT_COUNT_MAX - 1U; extra++) {
        size_t w = strlen(certd_exts_hex);
        memcpy(exts_hex, certd_exts_hex, w);
        for (size_t i = 0; i < extra; i++) {
            uint8_t small[11] = {0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, (uint8_t)(0x40 + i),
                                 0x04, 0x02, 0x30, 0x00};
            w += hex_encode(exts_hex + w, small, sizeof small);
        }
        n = certd_mint(alg, certd_serial_hex, certd_name_hex, leaf_hex, exts_hex, list);
        certd_row(alg, ca_hex, ca_key, ca_len, list, n,
                  extra == CH_X509_EXT_COUNT_MAX - 2 ? leaf_hex : NULL);
    }
}

// Mints one leaf whose whole certificate is exactly cert_target
// bytes, padding the subject SEQUENCE content — opaque to both
// parsers — with unread filler. The certificate size moves
// byte-for-byte with the filler once the header forms settle, so a
// few correction passes converge. The ECDSA signature INTEGERs
// re-pad with each new TBS hash, which jitters the size by a byte;
// when the estimate oscillates, a fresh serial redraws the
// signature. Returns the list length, or 0 when the target is
// unreachable.
static size_t certd_mint_sized(const char *alg, const char *leaf_hex, size_t cert_target,
                               uint8_t *list) {
    static char subject_hex[2 * CERTD_CERT_MAX + 1];
    static uint8_t subject[CERTD_CERT_MAX];
    char serial_hex[3];
    size_t filler = strlen(certd_name_hex) / 2;
    for (uint8_t serial = 0x2a; serial < 0x2a + 12; serial++) {
        (void)snprintf(serial_hex, sizeof serial_hex, "%02x", serial);
        for (int tries = 0; tries < 4; tries++) {
            memset(subject, 0x5a, filler);
            (void)hex_encode(subject_hex, subject, filler);
            size_t cert_len =
                certd_mint(alg, serial_hex, subject_hex, leaf_hex, certd_exts_hex, list) - 5;
            if (cert_len == cert_target) {
                return cert_len + 5;
            }
            long next = (long)filler + (long)cert_target - (long)cert_len;
            if (next <= 0 || (size_t)next > sizeof subject) {
                return 0;
            }
            filler = (size_t)next;
        }
    }
    return 0;
}

// The certificate size cap, as an exact pair per algorithm: a leaf
// padded to exactly the cap parses on both sides; one more byte
// fails. cap is the algorithm's x509.h default (768 for P-256, 1536
// for RSA) — the spec models the defaults, so a build that overrides
// CH_X509_MAX skips its own algorithm's pair.
static void certd_cap_rows(const char *alg, const char *ca_hex, const uint8_t *ca_key,
                           size_t ca_len, const char *leaf_hex) {
    size_t cap = strcmp(alg, "rsa") == 0 ? CH_X509_DEFAULT_MAX_RSA : CH_X509_DEFAULT_MAX_ECDSA;
    static uint8_t list[CERTD_CERT_MAX + 16];
    if (strcmp(alg, certd_build_alg) == 0 && (size_t)CH_X509_MAX != cap) {
        return;
    }
    for (size_t target = cap; target <= cap + 1; target++) {
        size_t n = certd_mint_sized(alg, leaf_hex, target, list);
        if (n == 0) {
            die("cert: cap boundary target unreachable");
        }
        certd_row(alg, ca_hex, ca_key, ca_len, list, n, target == cap ? leaf_hex : NULL);
    }
}

// The chain rows need certd_row and certd_mint, so their header
// joins the translation unit here, after both.
