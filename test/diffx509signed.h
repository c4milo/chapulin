// Randomized rows whose fields the spec re-signs. The driver hands
// x509mint a generated serial, validity or Extensions content, so the
// certificate carries a real CA signature and an accept is a real
// accept. This is the only lane that can tell a correct epoch reader
// from a broken one, because the epoch column exists only on an
// accept line.
//
// Families are stratified by row index rather than drawn at random.
// `make check` runs one fixed seed, so a family picked by weight
// either always appears or never does, and which one is an accident
// of the seed constant. Stratifying puts every family in every run
// and leaves the randomness in the digits inside each family.
//
// Included by diffx509.h after diffx509rand.h, whose pass context and
// row function this builds on.
#ifndef CH_DIFFX509SIGNED_H
#define CH_DIFFX509SIGNED_H

#define CERTD_MINT_VALIDITY_ROWS 52
#define CERTD_MINT_EXTS_ROWS 24
#define CERTD_MINT_SERIAL_ROWS 12
#define CERTD_MINT_FAMILY_COUNT 6
#define CERTD_MINT_EXTS_MAX 320
#define CERTD_MINT_SERIAL_MAX 22

// The two-digit values x509_der.c tests against, plus one value on
// each side of every bound.
static const unsigned certd_mint_years[9] = {0, 1, 24, 25, 48, 49, 50, 51, 99};
static const unsigned certd_mint_months[7] = {0, 1, 2, 11, 12, 13, 99};
static const unsigned certd_mint_days[7] = {0, 1, 2, 27, 28, 29, 99};

// Writes two ASCII digits: from the table three draws in four, and
// uniformly from 00..99 otherwise.
static void certd_mint_two_digits(char *out, const unsigned *table, size_t table_len) {
    unsigned value = rng_below(4) == 0 ? (unsigned)rng_below(100) : table[rng_below(table_len)];
    out[0] = (char)('0' + value / 10);
    out[1] = (char)('0' + value % 10);
}

// One UTCTime body, YYMMDD then six hours-minutes-seconds digits.
// hms_position names which of the six digits carries a nonzero value;
// CERTD_MINT_FAMILY_COUNT leaves all six at zero. x509_der.c sums the
// six digits, so a reader that dropped any one term still answers an
// epoch for the body that sets only that digit.
static void certd_mint_utc_body(char *body, size_t hms_position) {
    certd_mint_two_digits(body, certd_mint_years, 9);
    certd_mint_two_digits(body + 2, certd_mint_months, 7);
    certd_mint_two_digits(body + 4, certd_mint_days, 7);
    for (size_t i = 0; i < 6; i++) {
        body[6 + i] = '0';
    }
    if (hms_position < 6) {
        body[6 + hms_position] = (char)('1' + rng_below(9));
    }
    body[12] = 'Z';
}

// One GeneralizedTime body whose first twelve characters are
// themselves an epoch-shaped UTCTime body. A GeneralizedTime body is
// YYYYMMDDHHMMSS: read as a UTCTime body its first twelve characters
// are the century, the year, the month, and then the day, hour and
// minute standing in for hours-minutes-seconds. Setting the century
// to 00..49, the year to 01..12, the month to 01..28 and the day,
// hour and minute to zero makes those twelve characters pass every
// epoch test. A reader that lost the length guard in
// x509_read_time_epoch answers an epoch number here; the correct
// reader answers "-" because the tag is GeneralizedTime.
static void certd_mint_gt_prefix_body(char *body) {
    unsigned century = (unsigned)rng_below(50);
    unsigned year = 1 + (unsigned)rng_below(12);
    unsigned month = 1 + (unsigned)rng_below(28);
    unsigned second = (unsigned)rng_below(100);
    (void)snprintf(body, 16, "%02u%02u%02u000000%02uZ", century, year, month, second);
}

// One notBefore Time TLV as raw bytes, in the family the caller names.
static size_t certd_mint_not_before(uint8_t *out, unsigned family, size_t block) {
    char body[20];
    size_t body_len = 13;
    uint8_t tag = 0x17;
    switch (family) {
    case 0: // the epoch lattice, every bound and one value past it
        certd_mint_utc_body(body, CERTD_MINT_FAMILY_COUNT);
        break;
    case 1: // exactly one nonzero hours-minutes-seconds digit
        certd_mint_utc_body(body, block % 6);
        break;
    case 2: // GeneralizedTime whose first twelve characters are epoch-shaped
        certd_mint_gt_prefix_body(body);
        tag = 0x18;
        body_len = 15;
        break;
    case 3: // one byte of the body is not a digit
        certd_mint_utc_body(body, CERTD_MINT_FAMILY_COUNT);
        body[rng_below(2) == 0 ? 1 : rng_below(12)] = "\x2f\x3a\x41\x20"[rng_below(4)];
        break;
    default: // the tag and length forms that read_time_bytes rejects
        certd_mint_utc_body(body, CERTD_MINT_FAMILY_COUNT);
        if (rng_below(2) == 0) {
            tag = 0x18; // GeneralizedTime tag over a 13-byte body
        } else {
            body[12] = (char)('0' + rng_below(10)); // no trailing Z
        }
        break;
    }
    out[0] = tag;
    out[1] = (uint8_t)body_len;
    memcpy(out + 2, body, body_len);
    return body_len + 2;
}

// The validity SEQUENCE content: one generated notBefore plus the
// fixed notAfter, or one of the malformed assemblies family 5 sends.
// x509.c requires the content to hold exactly two Times.
static size_t certd_mint_validity(uint8_t *out, unsigned family, size_t block) {
    static uint8_t after[64];
    size_t after_len = strlen(certd_not_after_hex) / 2;
    if (!hex_decode(after, certd_not_after_hex, after_len)) {
        die("cert: malformed notAfter constant");
    }
    size_t n = certd_mint_not_before(out, family % 5, block);
    if (family < 5) {
        memcpy(out + n, after, after_len);
        return n + after_len;
    }
    switch (rng_below(4)) {
    case 0: // notBefore alone
        return n;
    case 1: // a third Time
        memcpy(out + n, after, after_len);
        memcpy(out + n + after_len, after, after_len);
        return n + 2 * after_len;
    case 2: // one trailing byte past the second Time
        memcpy(out + n, after, after_len);
        out[n + after_len] = (uint8_t)(rng_next() >> 56);
        return n + after_len + 1;
    default: // random bytes where the notAfter belongs
        rng_fill(out + n, after_len);
        return n + after_len;
    }
}

// One extension with an unrecognized extnID 2.5.29.<arc> and an empty
// SEQUENCE value, marked critical or not. An unknown extension marked
// critical must be rejected; an unknown one that is not is ignored.
static size_t certd_mint_ext_unknown(uint8_t *out, uint8_t arc, int critical) {
    static const uint8_t plain[11] = {0x30, 0x09, 0x06, 0x03, 0x55, 0x1d,
                                      0x00, 0x04, 0x02, 0x30, 0x00};
    static const uint8_t marked[14] = {0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x00,
                                       0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00};
    size_t n = critical ? sizeof marked : sizeof plain;
    memcpy(out, critical ? marked : plain, n);
    out[6] = arc;
    return n;
}

// The Extensions SEQUENCE content for one family. Every family keeps
// the profile's required keyUsage and extendedKeyUsage pair present
// unless it is deliberately breaking one of them, so most rows reach
// the signature check rather than stopping at the profile test.
static size_t certd_mint_exts(uint8_t *out, unsigned family) {
    static uint8_t required[64];
    static const uint8_t key_usage[16] = {0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
                                          0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80};
    size_t required_len = strlen(certd_exts_hex) / 2;
    if (!hex_decode(required, certd_exts_hex, required_len)) {
        die("cert: malformed extensions constant");
    }
    memcpy(out, required, required_len);
    size_t n = required_len;
    switch (family) {
    case 0: // the required pair alone; order is already covered above
        return n;
    case 1: { // one to six unknown extensions with drawn criticality
        size_t count = 1 + rng_below(6);
        for (size_t i = 0; i < count && n + 14 <= CERTD_MINT_EXTS_MAX; i++) {
            n += certd_mint_ext_unknown(out + n, (uint8_t)(0x20 + rng_below(0x40)),
                                        rng_below(2) != 0);
        }
        return n;
    }
    case 2: // a duplicate extnID
        memcpy(out + n, key_usage, sizeof key_usage);
        return n + sizeof key_usage;
    case 3: { // a keyUsage whose extnValue breaks a BIT STRING rule
        static const uint8_t broken[16] = {0x30, 0x0c, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01,
                                           0x01, 0xff, 0x04, 0x02, 0x03, 0x00, 0x00, 0x00};
        memcpy(out + n, broken, 14);
        return n + 14;
    }
    case 4: { // an extnID that breaks the minimal-subidentifier rule
        static const uint8_t padded[14] = {0x30, 0x0c, 0x06, 0x04, 0x55, 0x1d, 0x80,
                                           0x25, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80};
        memcpy(out + n, padded, sizeof padded);
        return n + sizeof padded;
    }
    default: { // enough extensions to cross the count bound
        size_t count = 5 + rng_below(5);
        for (size_t i = 0; i < count && n + 14 <= CERTD_MINT_EXTS_MAX; i++) {
            n += certd_mint_ext_unknown(out + n, (uint8_t)(0x30 + i), 0);
        }
        return n;
    }
    }
}

// The serial INTEGER value bytes for one family.
static size_t certd_mint_serial(uint8_t *out, unsigned family) {
    switch (family % 4) {
    case 0: // one byte, top bit clear, the canonical shape
        out[0] = (uint8_t)(1 + rng_below(0x7f));
        return 1;
    case 1: // a leading zero, which DER allows only before a set top bit
        out[0] = 0;
        out[1] = (uint8_t)(rng_next() >> 56);
        return 2;
    case 2: { // random bytes at and past the length the profile allows
        static const size_t lengths[6] = {1, 2, 19, 20, 21, 22};
        size_t n = lengths[rng_below(6)];
        rng_fill(out, n);
        return n;
    }
    default: // a single zero byte
        out[0] = 0;
        return 1;
    }
}

// Mints one leaf around the generated field slots and runs the
// inverted row. Every slot becomes text through hex_encode, the one
// place a field is rendered, so no slot can arrive empty or
// odd-length.
static void certd_mint_field_row(const certd_rand_ctx *ctx, const char *serial_hex,
                                 const char *validity_hex, const char *exts_hex) {
    static uint8_t list[CERTD_LIST_MAX];
    size_t n = certd_mint_dated(ctx->alg, serial_hex, validity_hex, certd_name_hex, ctx->leaf_hex,
                                exts_hex, list);
    certd_rand_row(ctx, list, n);
}

// The notBefore families. Exactly one size-bearing field moves, so the
// minted certificate stays near its baseline size and the mint reply
// cannot overrun the driver's buffer.
static void certd_mint_validity_rows(const certd_rand_ctx *ctx) {
    static uint8_t validity[128];
    static char validity_hex[257];
    static char serial_hex[8];
    (void)snprintf(serial_hex, sizeof serial_hex, "%s", certd_serial_hex);
    for (size_t i = 0; i < CERTD_MINT_VALIDITY_ROWS; i++) {
        size_t n = certd_mint_validity(validity, (unsigned)(i % CERTD_MINT_FAMILY_COUNT),
                                       i / CERTD_MINT_FAMILY_COUNT);
        (void)hex_encode(validity_hex, validity, n);
        certd_mint_field_row(ctx, serial_hex, validity_hex, certd_exts_hex);
    }
}

static void certd_mint_exts_rows(const certd_rand_ctx *ctx) {
    static uint8_t exts[CERTD_MINT_EXTS_MAX];
    static char exts_hex[2 * CERTD_MINT_EXTS_MAX + 1];
    for (size_t i = 0; i < CERTD_MINT_EXTS_ROWS; i++) {
        size_t n = certd_mint_exts(exts, (unsigned)(i % CERTD_MINT_FAMILY_COUNT));
        (void)hex_encode(exts_hex, exts, n);
        certd_mint_field_row(ctx, certd_serial_hex, certd_validity_hex, exts_hex);
    }
}

static void certd_mint_serial_rows(const certd_rand_ctx *ctx) {
    static uint8_t serial[CERTD_MINT_SERIAL_MAX];
    static char serial_hex[2 * CERTD_MINT_SERIAL_MAX + 1];
    for (size_t i = 0; i < CERTD_MINT_SERIAL_ROWS; i++) {
        size_t n = certd_mint_serial(serial, (unsigned)i);
        (void)hex_encode(serial_hex, serial, n);
        certd_mint_field_row(ctx, serial_hex, certd_validity_hex, certd_exts_hex);
    }
}

// The sharp lane for one pass.
static void certd_mint_rows(const certd_rand_ctx *ctx) {
    certd_mint_validity_rows(ctx);
    certd_mint_exts_rows(ctx);
    certd_mint_serial_rows(ctx);
}

#endif
