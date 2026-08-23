// The epoch boundary rows of the certificate differential: the one
// row family that varies the leaf's notBefore, so it is the family
// that drives the accept line's epoch column. Included by diff_x509.h
// after certd_mint_dated and certd_row, the diff_x509_bounds.h
// pattern; test/diff_test.c is the one translation unit.
#ifndef CH_DIFFX509EPOCH_H
#define CH_DIFFX509EPOCH_H

// Epoch boundary rows: only the notBefore moves, every leaf stays
// inside the grammar both sides accept, and only the epoch column
// changes. The exact pairs: the first and last allowed dates, the
// last valid day against the first day past the end, the first
// invalid year, plus the off-column shapes (nonzero seconds,
// GeneralizedTime, a non-digit body).
static void certd_epoch_rows(const char *alg, const char *ca_hex, const uint8_t *ca_key,
                             size_t ca_len, const char *leaf_hex) {
    static const struct {
        const char *not_before_hex;
        const char *column;
    } rows[9] = {
        {"170d3030303130313030303030305a",     "0"    }, // 000101000000Z, the first allowed date
        {"170d3439313232383030303030305a",     "16799"}, // 491228000000Z, the last allowed date
        {"170d3530303130313030303030305a",     "-"    }, // 500101000000Z, the first invalid year
        {"170d3030303132383030303030305a",     "27"   }, // 000128000000Z, the last valid day
        {"170d3030303132393030303030305a",     "-"    }, // 000129000000Z, the first day not allowed
        {"170d3030303130313030303030315a",     "-"    }, // 000101000001Z, nonzero seconds
        {"180f32303030303130313030303030305a", "-"    }, // GeneralizedTime 20000101000000Z
        // GeneralizedTime 20010300000000Z: read as a UTCTime body its
        // first twelve digits are an epoch date (yy 20, mm 01, dd 03,
        // midnight), so a reader that stopped checking the tag would
        // answer 6722 here while the row above still looked right.
        {"180f32303031303330303030303030305a", "-"    },
        {"170d3041303130313030303030305a",     "-"    }, // 0A0101000000Z, a non-digit body
    };
    static uint8_t list[CERTD_CERT_MAX + 16];
    static char validity_hex[80];
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        (void)snprintf(validity_hex, sizeof validity_hex, "%s%s", rows[i].not_before_hex,
                       certd_not_after_hex);
        size_t n = certd_mint_dated(alg, certd_serial_hex, validity_hex, certd_name_hex, leaf_hex,
                                    certd_exts_hex, list);
        certd_epoch_want = rows[i].column;
        certd_row(alg, ca_hex, ca_key, ca_len, list, n, leaf_hex);
        certd_epoch_want = "8400";
    }
}

#endif
