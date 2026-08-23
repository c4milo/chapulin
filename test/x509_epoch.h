// Revocation-epoch cases for the certificate grammar suite: the
// date boundaries x509_read_time_epoch draws. ch_connect's epoch
// gates need the whole library, so they live in session_tests.h
// beside the other config cases. Included by
// x509_strict_test.c after its vectors and helpers, the
// x509_chain_tests.h pattern; not a standalone translation unit.

// Runs one Time TLV through the extracting reader. Returns the
// reader's shape verdict and reports the extraction through the two
// out-parameters, so a case can state all three outcomes at once.
// Wraps digits as a Time TLV. The caller passes the digits without
// the zone byte, and the buffer needs strlen(digits) + 3 bytes.
static size_t put_time(uint8_t *buf, const char *digits, uint8_t tag) {
    size_t n = strlen(digits);
    buf[0] = tag;
    buf[1] = (uint8_t)(n + 1);
    memcpy(buf + 2, digits, n);
    buf[2 + n] = 'Z';
    return n + 3;
}

static int read_epoch(const char *ascii, uint8_t tag, uint32_t *index, int *ok) {
    uint8_t buf[32];
    size_t total = put_time(buf, ascii, tag);
    rbuf r;
    rb_init(&r, buf, total);
    *index = 0xffffffff;
    *ok = -1;
    return x509_read_time_epoch(&r, index, ok);
}

// An epoch-shaped UTCTime yielding exactly the expected index.
static int epoch_is(const char *ascii, uint32_t want) {
    uint32_t index = 0;
    int ok = 0;
    return read_epoch(ascii, 0x17, &index, &ok) == 1 && ok == 1 && index == want;
}

// A Time the grammar still accepts, carrying no epoch.
static int epoch_absent(const char *ascii, uint8_t tag) {
    uint32_t index = 0;
    int ok = 0;
    return read_epoch(ascii, tag, &index, &ok) == 1 && ok == 0;
}

// Bytes the grammar rejects outright: no Time, so no epoch either.
static int epoch_unreadable(const char *ascii, uint8_t tag) {
    uint32_t index = 0;
    int ok = 0;
    return read_epoch(ascii, tag, &index, &ok) == 0;
}

// Each boundary twice: the last value the reader admits, then the
// first one past it. The formula itself is pinned at both endpoints
// and at one interior point no single-term error can reproduce.
static void test_epoch_dates(void) {
    CHECK(epoch_is("000101000000", 0));            // the first allowed date
    CHECK(epoch_is("491228000000", CH_EPOCH_MAX)); // the last
    CHECK(epoch_is("010203000000", 336 + 28 + 2));

    // Year: 49 is the last UTCTime year allowed, and 50 is
    // where RFC 5280 starts reading the last century.
    CHECK(epoch_is("490101000000", 49 * 336));
    CHECK(epoch_absent("500101000000", 0x17));

    // Month: 12 in, 13 out, 00 out.
    CHECK(epoch_is("001201000000", 11 * 28));
    CHECK(epoch_absent("001301000000", 0x17));
    CHECK(epoch_absent("000001000000", 0x17));

    // Day: 28 in, 29 out, 00 out.
    CHECK(epoch_is("000128000000", 27));
    CHECK(epoch_absent("000129000000", 0x17));
    CHECK(epoch_absent("000100000000", 0x17));

    // Time of day: only midnight is allowed, and each of the
    // three fields carries the rule on its own.
    CHECK(epoch_absent("000101010000", 0x17));
    CHECK(epoch_absent("000101000100", 0x17));
    CHECK(epoch_absent("000101000001", 0x17));

    // Shapes the grammar takes but the epoch rules do not: a
    // GeneralizedTime, and a body that is not all digits. The second
    // GeneralizedTime is the discriminating one: read as a UTCTime
    // body, its first twelve digits are an epoch date (yy 20, mm 01,
    // dd 03, midnight), so a reader that stopped checking the tag
    // would answer index 6722 here while the case above still looked
    // correct. Mutation testing found the gap.
    CHECK(epoch_absent("20000101000000", 0x18));
    CHECK(epoch_absent("20010300000000", 0x18));
    CHECK(epoch_absent("0A0101000000", 0x17));
    CHECK(epoch_absent("00010100000/", 0x17));
    CHECK(epoch_absent("00010100000:", 0x17));

    // Shapes the grammar refuses: the zone byte, and each tag at the
    // other tag's length.
    CHECK(epoch_unreadable("000101000000", 0x16));
    {
        uint8_t buf[4] = {0x17, 0x0d, '0', '0'};
        rbuf r;
        rb_init(&r, buf, sizeof buf);
        uint32_t index = 0;
        int ok = 0;
        CHECK(x509_read_time_epoch(&r, &index, &ok) == 0); // truncated body
    }
}

// The reader's verdict on a Time's shape must stay exactly
// x509_read_time's: extraction may never widen or narrow the
// grammar. The CBMC harness proves this over unconstrained bytes;
// these rows pin the shapes a certificate actually carries.
static void test_epoch_grammar_unchanged(void) {
    static const struct {
        const char *ascii;
        uint8_t tag;
    } shapes[7] = {
        {"000101000000",   0x17},
        {"500101000000",   0x17},
        {"20000101000000", 0x18},
        {"0A0101000000",   0x17},
        {"000101000000",   0x16},
        {"2000010100000",  0x18},
        {"20010300000000", 0x18},
    };
    for (size_t i = 0; i < 7; i++) {
        uint8_t buf[32];
        size_t total = put_time(buf, shapes[i].ascii, shapes[i].tag);

        rbuf plain;
        rb_init(&plain, buf, total);
        int plain_rc = x509_read_time(&plain);

        rbuf epoch;
        rb_init(&epoch, buf, total);
        uint32_t index = 0;
        int ok = 0;
        int epoch_rc = x509_read_time_epoch(&epoch, &index, &ok);

        CHECK(plain_rc == epoch_rc);
        CHECK(plain.err == epoch.err);
        CHECK(rb_left(&plain) == rb_left(&epoch));
    }
}

// A real certificate's own notBefore, and a spliced epoch date in
// its place. The vectors carry an ordinary issuance time, so they
// must come back with no epoch at all: extraction stays permissive,
// and only a CA that opts in writes epoch dates.
static void test_epoch_from_chain(void) {
    CHECK(run_cert(good_cert, good_cert_len) == CH_OK);
    CHECK(last_info.epoch_ok == 0); // 260821054655Z: a wall-clock time
    CHECK(last_info.epoch == 0);

    // The same leaf with an epoch-shaped validity spliced in. The
    // splice breaks the CA signature, so unknown_ca is the verdict
    // that proves the grammar accepted the certificate — and the
    // epoch comes out of the parse that got that far.
    uint8_t validity[40];
    size_t vn = 2;
    vn += put_time(validity + vn, "000103000000", 0x17);
    vn += put_time(validity + vn, "491231235959", 0x17);
    validity[0] = 0x30;
    validity[1] = (uint8_t)(vn - 2);

    size_t off = tbs_field(good_cert, good_cert_len, 4); // validity
    size_t n = mutate(off, tlv_total(good_cert, good_cert_len, off), validity, vn);
    CHECK(run_cert(mutant_a, n) == CH_EAUTH);
    CHECK(last_alert == ALERT_UNKNOWN_CA);
    CHECK(last_info.epoch_ok == 1);
    CHECK(last_info.epoch == 2); // 000103000000Z is the third allowed date

    // Through a two-entry chain, the epoch still comes from the leaf.
    // The intermediate's own dates are never read.
    CHECK(run_pair(chain_leaf, chain_leaf_len, chain_int, chain_int_len) == CH_OK);
    CHECK(last_info.epoch_ok == 0); // the vectors' wall-clock dates again
}
