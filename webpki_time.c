// Dates for the web PKI trust mode (TRUST=webpki): a certificate's two
// Time values, and the caller's clock, each as one packed decimal
// number YYYYMMDDHHMMSS, so that notBefore <= now <= notAfter is three
// integer compares. Contract in webpki.h; the rules in docs/webpki.md
// ("Validity"). Every byte here is public — a certificate's dates, or
// the caller's own clock — so variable time is fine and deliberate.
#include "webpki.h"

#include "buf.h"
#include "x509.h"

// The decimal weight of each field in the packed form.
#define PACK_YEAR UINT64_C(10000000000)
#define PACK_MONTH UINT64_C(100000000)
#define PACK_DAY UINT64_C(1000000)
#define PACK_HOUR UINT64_C(10000)
#define PACK_MINUTE UINT64_C(100)

// The last second of the year 9999: 9999-12-31T23:59:59Z.
#define SECONDS_MAX UINT64_C(253402300799)

// The RFC 5280 §4.1.2.5 Time shapes: UTCTime YYMMDDHHMMSSZ and
// GeneralizedTime YYYYMMDDHHMMSSZ, zulu only.
#define TAG_UTC_TIME 0x17
#define TAG_GENERALIZED_TIME 0x18
#define UTC_TIME_LEN 13
#define GENERALIZED_TIME_LEN 15

typedef struct {
    uint32_t year;
    uint32_t month;
    uint32_t day;
    uint32_t hour;
    uint32_t minute;
    uint32_t second;
} civil_time;

// Days in each month of a common year, indexed by month number.
static const uint8_t month_days[13] = {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

static uint64_t pack(const civil_time *t) {
    return (uint64_t)t->year * PACK_YEAR + (uint64_t)t->month * PACK_MONTH +
           (uint64_t)t->day * PACK_DAY + (uint64_t)t->hour * PACK_HOUR +
           (uint64_t)t->minute * PACK_MINUTE + t->second;
}

// One two-digit decimal field. A byte outside '0'..'9' wraps the
// unsigned difference past 9 and is refused.
static int read_pair(const uint8_t *c, uint32_t *out) {
    uint32_t hi = (uint32_t)c[0] - '0';
    uint32_t lo = (uint32_t)c[1] - '0';
    if (hi > 9 || lo > 9) {
        return 0;
    }
    *out = hi * 10 + lo;
    return 1;
}

// The year as its century and its two low digits. UTCTime encodes the
// low digits only, and RFC 5280 §4.1.2.5 fixes the century: 50..99 is
// 1950..1999, 00..49 is 2000..2049. GeneralizedTime encodes all four
// digits and is admitted from 2050 on, because the same section makes
// UTCTime the only encoding of a date through 2049.
static int read_year(const uint8_t *c, size_t body_len, uint32_t *century, uint32_t *low) {
    if (body_len == UTC_TIME_LEN) {
        if (!read_pair(c, low)) {
            return 0;
        }
        *century = *low >= 50 ? 19 : 20;
        return 1;
    }
    if (!read_pair(c, century) || !read_pair(c + 2, low)) {
        return 0;
    }
    return *century * 100 + *low >= 2050;
}

// The five two-digit fields after the year: month, day, hour, minute,
// second.
static int read_clock(const uint8_t *c, civil_time *t) {
    return read_pair(c, &t->month) && read_pair(c + 2, &t->day) && read_pair(c + 4, &t->hour) &&
           read_pair(c + 6, &t->minute) && read_pair(c + 8, &t->second);
}

// Month 1..12, day 1..the month's length in that year, hour 0..23,
// minute and second 0..59. leap is the caller's verdict on the year.
static int fields_in_range(const civil_time *t, int leap) {
    if (t->month < 1 || t->month > 12) {
        return 0;
    }
    uint32_t days = month_days[t->month];
    if (t->month == 2 && leap) {
        days = 29;
    }
    return t->day >= 1 && t->day <= days && t->hour <= 23 && t->minute <= 59 && t->second <= 59;
}

// The Gregorian leap rule on the year's two halves, with no division:
// the year is a multiple of 4 exactly when its low two digits are
// (100 is a multiple of 4); it is a multiple of 100 exactly when they
// are zero; and then a multiple of 400 exactly when the century is a
// multiple of 4.
static int is_leap_year(uint32_t century, uint32_t low) {
    if (low != 0) {
        return (low & 3U) == 0;
    }
    return (century & 3U) == 0;
}

// The body of one Time, its length already checked against its tag:
// the year, the five clock fields, the trailing 'Z'.
static int read_body(const uint8_t *c, size_t body_len, civil_time *t) {
    uint32_t century = 0;
    uint32_t low = 0;
    if (!read_year(c, body_len, &century, &low)) {
        return 0;
    }
    size_t at = body_len == UTC_TIME_LEN ? 2 : 4;
    if (!read_clock(c + at, t) || c[body_len - 1] != 'Z') {
        return 0;
    }
    t->year = century * 100 + low;
    return fields_in_range(t, is_leap_year(century, low));
}

int webpki_read_time(rbuf *r, uint64_t *packed) {
    uint8_t tag = rb_u8(r);
    size_t body_len = 0;
    if (tag == TAG_UTC_TIME) {
        body_len = UTC_TIME_LEN;
    } else if (tag == TAG_GENERALIZED_TIME) {
        body_len = GENERALIZED_TIME_LEN;
    } else {
        return 0;
    }
    size_t len = 0;
    if (!x509_read_len(r, &len) || len != body_len) {
        return 0;
    }
    const uint8_t *c = rb_bytes(r, body_len);
    if (c == NULL) {
        return 0;
    }
    civil_time t;
    if (!read_body(c, body_len, &t)) {
        return 0;
    }
    *packed = pack(&t);
    return 1;
}

// Days since 1970-01-01 to a proleptic Gregorian date, by Howard
// Hinnant's civil_from_days. It counts years from March, so February
// and its leap day end the year. An era is 400 years, 146097 days, the
// Gregorian calendar's period. Every quantity is non-negative, so the
// arithmetic is unsigned. days is at most 2932896 (the last day of the
// year 9999), so nothing here nears the uint32 range.
static void civil_from_days(uint32_t days, civil_time *t) {
    // 719468 days separate 0000-03-01 from 1970-01-01.
    uint32_t days_since_march_0000 = days + 719468;
    uint32_t era = days_since_march_0000 / 146097;
    // [0, 146096]
    uint32_t day_of_era = days_since_march_0000 - era * 146097;
    // [0, 399]
    uint32_t year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    // [0, 365], 0 is March 1
    uint32_t day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    // [0, 11], 0 is March
    uint32_t month_from_march = (5 * day_of_year + 2) / 153;
    // [1, 31]
    t->day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    // [1, 12]
    t->month = month_from_march < 10 ? month_from_march + 3 : month_from_march - 9;
    t->year = year_of_era + era * 400 + (t->month <= 2 ? 1U : 0U);
}

// A clock past SECONDS_MAX packs as that instant, 99991231235959: the
// value RFC 5280 §4.1.2.5 gives a certificate with no well-defined
// expiration, and the largest value webpki_read_time produces. So the
// result never leaves the packed range, and a later clock never packs
// lower than an earlier one.
uint64_t webpki_pack_seconds(uint64_t now_seconds) {
    if (now_seconds > SECONDS_MAX) {
        now_seconds = SECONDS_MAX;
    }
    civil_time t;
    civil_from_days((uint32_t)(now_seconds / 86400), &t);
    uint32_t second_of_day = (uint32_t)(now_seconds % 86400);
    t.hour = second_of_day / 3600;
    uint32_t second_of_hour = second_of_day - t.hour * 3600;
    t.minute = second_of_hour / 60;
    t.second = second_of_hour - t.minute * 60;
    return pack(&t);
}
