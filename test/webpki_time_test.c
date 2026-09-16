// The TRUST=webpki date reader and clock packer at their boundaries:
// the UTCTime century split at 49/50, the GeneralizedTime floor at
// 2050, every field's range on both sides of its edge, the leap rule
// at 2024, 2023, 2000 and 2100, the shape rules (tag, length, zone,
// digits), and the packed compare the validity check uses, with now at
// notAfter accepted and one second later refused. Its own binary
// because only the TRUST=webpki object reads a date; the module stays
// testable without the rest of the stack, the way sha512_test does.
//
// Every epoch value below was produced with Python's datetime over
// the proleptic Gregorian calendar, e.g. 951782400 is
// datetime(2000, 2, 29, tzinfo=utc).timestamp().
#include <stdio.h>
#include <string.h>

#include "buf.h"
#include "webpki.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

// Reads one Time from raw TLV bytes; returns the reader's verdict and
// leaves the packed value and the bytes left unread in the outputs.
static int read_raw(const uint8_t *tlv, size_t tlv_len, uint64_t *packed, size_t *left) {
    rbuf r;
    rb_init(&r, tlv, tlv_len);
    *packed = 0;
    int rc = webpki_read_time(&r, packed);
    *left = rb_left(&r);
    return rc;
}

// Frames body under tag with a short-form length and reads it.
static int read_time(uint8_t tag, const char *body, uint64_t *packed) {
    uint8_t tlv[32];
    size_t body_len = strlen(body);
    tlv[0] = tag;
    tlv[1] = (uint8_t)body_len;
    memcpy(tlv + 2, body, body_len);
    size_t left = 0;
    return read_raw(tlv, body_len + 2, packed, &left);
}

static void accept(uint8_t tag, const char *body, uint64_t want) {
    uint64_t packed = 0;
    CHECK(read_time(tag, body, &packed) == 1);
    CHECK(packed == want);
}

static void refuse(uint8_t tag, const char *body) {
    uint64_t packed = 0;
    CHECK(read_time(tag, body, &packed) == 0);
}

#define UTC 0x17
#define GEN 0x18

// RFC 5280 §4.1.2.5: UTCTime YY 49 is 2049 and 50 is 1950; a
// GeneralizedTime year through 2049 is refused and 2050 accepted.
static void test_year_boundaries(void) {
    accept(UTC, "490101000000Z", UINT64_C(20490101000000));
    accept(UTC, "500101000000Z", UINT64_C(19500101000000));
    accept(UTC, "000101000000Z", UINT64_C(20000101000000));
    accept(UTC, "991231235959Z", UINT64_C(19991231235959));
    refuse(GEN, "20490101000000Z");
    refuse(GEN, "20491231235959Z");
    accept(GEN, "20500101000000Z", UINT64_C(20500101000000));
    accept(GEN, "99991231235959Z", UINT64_C(99991231235959));
    refuse(GEN, "19700101000000Z");
    refuse(GEN, "00000101000000Z");
}

// Each field on both sides of its edge.
static void test_field_ranges(void) {
    accept(GEN, "20501201000000Z", UINT64_C(20501201000000));
    refuse(GEN, "20501301000000Z");
    refuse(GEN, "20500001000000Z");
    accept(GEN, "20500131000000Z", UINT64_C(20500131000000));
    refuse(GEN, "20500132000000Z");
    refuse(GEN, "20500100000000Z");
    accept(GEN, "20500430000000Z", UINT64_C(20500430000000));
    refuse(GEN, "20500431000000Z");
    accept(GEN, "20500101230000Z", UINT64_C(20500101230000));
    refuse(GEN, "20500101240000Z");
    accept(GEN, "20500101005900Z", UINT64_C(20500101005900));
    refuse(GEN, "20500101006000Z");
    accept(GEN, "20500101000059Z", UINT64_C(20500101000059));
    refuse(GEN, "20500101000060Z");
    accept(UTC, "491231235959Z", UINT64_C(20491231235959));
    refuse(UTC, "491232235959Z");
    refuse(UTC, "491331235959Z");
    refuse(UTC, "491231245959Z");
    refuse(UTC, "491231236059Z");
    refuse(UTC, "491231235960Z");
}

// The Gregorian leap rule: 2024 and 2000 (a multiple of 400) have a
// February 29; 2023 and 2100 (a multiple of 100 only) do not.
static void test_leap_years(void) {
    accept(UTC, "240229000000Z", UINT64_C(20240229000000));
    refuse(UTC, "230229000000Z");
    accept(UTC, "000229000000Z", UINT64_C(20000229000000));
    refuse(UTC, "230230000000Z");
    refuse(UTC, "240230000000Z");
    accept(UTC, "240228000000Z", UINT64_C(20240228000000));
    refuse(GEN, "21000229000000Z");
    accept(GEN, "21000228000000Z", UINT64_C(21000228000000));
    accept(GEN, "24000229000000Z", UINT64_C(24000229000000));
    accept(GEN, "20960229000000Z", UINT64_C(20960229000000));
    refuse(GEN, "20970229000000Z");
}

// The shape: only 'Z', only digits, exactly 13 or 15 body bytes under
// the matching tag, a minimal length, no other tag, no truncation.
static void test_shapes(void) {
    refuse(GEN, "20500101000000+");
    refuse(GEN, "20500101000000z");
    refuse(GEN, "2050010100000Z0");
    refuse(GEN, "2050010100000aZ");
    refuse(GEN, "205001010000 0Z");
    refuse(UTC, "49010100000/Z");
    refuse(UTC, "490101000000");
    refuse(UTC, "4901010000000Z");
    refuse(UTC, "20490101000000Z");
    refuse(GEN, "490101000000Z");
    refuse(GEN, "205001010000000Z");
    refuse(0x13, "20500101000000Z");
    refuse(0x17 | 0x20, "490101000000Z");

    uint64_t packed = 0;
    size_t left = 0;
    // A non-minimal length octet for the same 13 bytes.
    static const uint8_t long_form[] = {0x17, 0x81, 0x0d, '4', '9', '0', '1', '0',
                                        '1',  '0',  '0',  '0', '0', '0', '0', 'Z'};
    CHECK(read_raw(long_form, sizeof long_form, &packed, &left) == 0);
    // The length claims 15 bytes and 10 follow.
    static const uint8_t cut[] = {0x18, 0x0f, '2', '0', '5', '0', '0', '1', '0', '1', '0', '0'};
    CHECK(read_raw(cut, sizeof cut, &packed, &left) == 0);
    // Nothing at all, and a lone tag.
    CHECK(read_raw(cut, 0, &packed, &left) == 0);
    CHECK(read_raw(cut, 1, &packed, &left) == 0);
    // The length octet must name the shape's own length. Both of these
    // carry a valid UTCTime in their first 13 bytes, so a reader that
    // took the tag's fixed length for the field's length would read
    // them and accept: only the equality refuses them.
    static const uint8_t over[] = {0x17, 0x0e, '4', '9', '0', '1', '0', '1',
                                   '0',  '0',  '0', '0', '0', '0', 'Z', 'Z'};
    CHECK(read_raw(over, sizeof over, &packed, &left) == 0);
    static const uint8_t under[] = {0x17, 0x0c, '4', '9', '0', '1', '0', '1',
                                    '0',  '0',  '0', '0', '0', '0', 'Z'};
    CHECK(read_raw(under, sizeof under, &packed, &left) == 0);
    // Bytes after the Time are left for the caller: the reader
    // consumes exactly one TLV.
    static const uint8_t trailing[] = {0x18, 0x0f, '2', '0', '5', '0', '0', '1',  '0', '1',
                                       '0',  '0',  '0', '0', '0', '0', 'Z', 0xaa, 0xbb};
    CHECK(read_raw(trailing, sizeof trailing, &packed, &left) == 1);
    CHECK(packed == UINT64_C(20500101000000));
    CHECK(left == 2);
}

static void test_pack_seconds(void) {
    CHECK(webpki_pack_seconds(0) == UINT64_C(19700101000000));
    CHECK(webpki_pack_seconds(1) == UINT64_C(19700101000001));
    CHECK(webpki_pack_seconds(86399) == UINT64_C(19700101235959));
    CHECK(webpki_pack_seconds(86400) == UINT64_C(19700102000000));
    CHECK(webpki_pack_seconds(946684799) == UINT64_C(19991231235959));
    CHECK(webpki_pack_seconds(946684800) == UINT64_C(20000101000000));
    CHECK(webpki_pack_seconds(951782400) == UINT64_C(20000229000000));
    CHECK(webpki_pack_seconds(1709210096) == UINT64_C(20240229123456));
    CHECK(webpki_pack_seconds(2147483647) == UINT64_C(20380119031407));
    CHECK(webpki_pack_seconds(4102444800) == UINT64_C(21000101000000));
    CHECK(webpki_pack_seconds(4107542399) == UINT64_C(21000228235959));
    CHECK(webpki_pack_seconds(4107542400) == UINT64_C(21000301000000));
    CHECK(webpki_pack_seconds(13574563200) == UINT64_C(24000229000000));
    // The last second of the year 9999, and the clamp past it.
    CHECK(webpki_pack_seconds(253402300798) == UINT64_C(99991231235958));
    CHECK(webpki_pack_seconds(253402300799) == UINT64_C(99991231235959));
    CHECK(webpki_pack_seconds(253402300800) == UINT64_C(99991231235959));
    CHECK(webpki_pack_seconds(UINT64_MAX) == UINT64_C(99991231235959));
}

// notBefore <= now <= notAfter as three packed compares, at both ends:
// now equal to notAfter passes and one second later fails; now equal
// to notBefore passes and one second earlier fails.
static void test_validity_compare(void) {
    uint64_t not_before = 0;
    uint64_t not_after = 0;
    CHECK(read_time(GEN, "20500101000000Z", &not_before) == 1);
    CHECK(read_time(GEN, "20501231235959Z", &not_after) == 1);
    uint64_t at_not_after = webpki_pack_seconds(2556143999);
    CHECK(at_not_after == not_after);
    CHECK(not_before <= at_not_after && at_not_after <= not_after);
    uint64_t past_not_after = webpki_pack_seconds(2556143999 + 1);
    CHECK(past_not_after == UINT64_C(20510101000000));
    CHECK(!(past_not_after <= not_after));
    uint64_t at_not_before = webpki_pack_seconds(2524608000);
    CHECK(at_not_before == not_before);
    CHECK(not_before <= at_not_before && at_not_before <= not_after);
    uint64_t before_not_before = webpki_pack_seconds(2524608000 - 1);
    CHECK(before_not_before == UINT64_C(20491231235959));
    CHECK(!(not_before <= before_not_before));
}

int main(void) {
    test_year_boundaries();
    test_field_ranges();
    test_leap_years();
    test_shapes();
    test_pack_seconds();
    test_validity_compare();
    if (failures == 0) {
        (void)printf("webpki_time: all tests passed\n");
    }
    return failures != 0;
}
