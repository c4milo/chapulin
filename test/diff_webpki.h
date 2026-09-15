// Web PKI dates and hostnames differential section: the four
// TRUST=webpki routines that read no certificate, each against the
// Lean spec on the same bytes.
//
// Times come three ways: a valid random date under the tag its year
// takes; that date with one field pushed out of range, one digit
// replaced, or its tag, length or zone byte changed; and raw random
// bytes. The clock op takes fixed edges, random seconds inside the
// admitted range, and random whole uint64 values, which both sides
// clamp. Hostnames and presented names are drawn over the seven-byte
// alphabet {a, b, A, -, ., *, NUL} at lengths 0..16, the space
// docs/webpki.md says the differential should cover: every byte is
// either in the reference-name alphabet on one side of a rule or the
// one byte a rule exists to refuse. Half the hosts derive from the
// presented name — case flipped, or one label put under a wildcard —
// so matches happen often enough to be compared, not only refusals.
// GeneralName tags are drawn from the nine RFC 5280 admits, the first
// byte of the high-tag-number form, a constructed dNSName and any byte
// at all, so a tag that one side skips and the other refuses fails the
// run.
// Included by test/diff_test.c after diff_driver.h (single translation
// unit).
#ifndef CH_DIFF_WEBPKI_H
#define CH_DIFF_WEBPKI_H

#include "buf.h"
#include "webpki.h"

#define WEBPKI_DIFF_NAME_MAX 16
#define WEBPKI_DIFF_SAN_MAX 128
#define WEBPKI_DIFF_TIME_MAX 24
#define WEBPKI_DIFF_SECONDS_MAX UINT64_C(253402300799)

static const uint8_t webpki_diff_alphabet[] = {'a', 'b', 'A', '-', '.', '*', 0};

static void webpki_diff_name(uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        out[i] = webpki_diff_alphabet[rng_below(sizeof webpki_diff_alphabet)];
    }
}

// Writes two decimal digits of v (0..99).
static void webpki_diff_put_pair(uint8_t *out, uint32_t v) {
    out[0] = (uint8_t)('0' + v / 10);
    out[1] = (uint8_t)('0' + v % 10);
}

// A valid random Time TLV: the year picks the tag, UTCTime through
// 2049 and GeneralizedTime from 2050. Every day is drawn inside its
// month, February at 28 so no leap rule is needed here; the perturbed
// rows and the unit vectors cover the 29th. Returns the TLV length.
static size_t webpki_diff_valid_time(uint8_t *tlv) {
    static const uint8_t month_days[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    uint32_t year = 1950 + (uint32_t)rng_below(9999 - 1950 + 1);
    uint32_t month = 1 + (uint32_t)rng_below(12);
    uint32_t day = 1 + (uint32_t)rng_below(month_days[month - 1]);
    uint8_t *body = tlv + 2;
    size_t at = 0;
    if (year < 2050) {
        tlv[0] = 0x17;
        tlv[1] = 13;
        webpki_diff_put_pair(body, year % 100);
        at = 2;
    } else {
        tlv[0] = 0x18;
        tlv[1] = 15;
        webpki_diff_put_pair(body, year / 100);
        webpki_diff_put_pair(body + 2, year % 100);
        at = 4;
    }
    webpki_diff_put_pair(body + at, month);
    webpki_diff_put_pair(body + at + 2, day);
    webpki_diff_put_pair(body + at + 4, (uint32_t)rng_below(24));
    webpki_diff_put_pair(body + at + 6, (uint32_t)rng_below(60));
    webpki_diff_put_pair(body + at + 8, (uint32_t)rng_below(60));
    body[at + 10] = 'Z';
    return (size_t)tlv[1] + 2;
}

// One perturbation of a valid Time: a field replaced by an out-of-range
// or edge value (13 for the month, 29..32 for the day, 24 for the
// hour, 60 for a minute or second), one body byte replaced, or the
// tag, length or zone byte changed. Perturbed rows still go to the
// spec as whatever they are; the C verdict is what the row compares.
static void webpki_diff_perturb_time(uint8_t *tlv, size_t tlv_len) {
    size_t at = tlv[0] == 0x17 ? 2 : 4;
    uint8_t *body = tlv + 2;
    switch (rng_below(8)) {
    case 0:
        webpki_diff_put_pair(body + at, 13 - (uint32_t)rng_below(2));
        break;
    case 1:
        webpki_diff_put_pair(body + at + 2, 29 + (uint32_t)rng_below(4));
        break;
    case 2:
        webpki_diff_put_pair(body + at + 4, 24);
        break;
    case 3:
        webpki_diff_put_pair(body + at + 6 + 2 * rng_below(2), 60);
        break;
    case 4:
        body[rng_below(tlv_len - 2)] = (uint8_t)rng_next();
        break;
    case 5:
        tlv[0] = (uint8_t)(rng_below(2) ? 0x17 : 0x18);
        break;
    case 6:
        tlv[1] = (uint8_t)(12 + rng_below(5));
        break;
    default:
        body[tlv_len - 3] = (uint8_t)rng_next();
        break;
    }
}

static void diff_webpki_time(void) {
    for (int i = 0; i < 600; i++) {
        uint8_t tlv[WEBPKI_DIFF_TIME_MAX];
        size_t tlv_len = 0;
        if (i % 3 == 2) {
            tlv_len = 13 + rng_below(WEBPKI_DIFF_TIME_MAX - 13 + 1);
            rng_fill(tlv, tlv_len);
            tlv[0] = (uint8_t)(rng_below(2) ? 0x17 : 0x18);
            tlv[1] = (uint8_t)(13 + 2 * rng_below(2));
        } else {
            tlv_len = webpki_diff_valid_time(tlv);
            if (i % 3 == 1) {
                webpki_diff_perturb_time(tlv, tlv_len);
            }
        }
        // Trailing bytes on some rows: the reader consumes one TLV.
        size_t extra = rng_below(3);
        if (tlv_len + extra > sizeof tlv) {
            extra = 0;
        }
        rng_fill(tlv + tlv_len, extra);
        tlv_len += extra;
        rbuf r;
        rb_init(&r, tlv, tlv_len);
        uint64_t packed = 0;
        char want[64];
        if (webpki_read_time(&r, &packed)) {
            (void)snprintf(want, sizeof want, "ok %llu %zu", (unsigned long long)packed,
                           tlv_len - rb_left(&r));
        } else {
            (void)snprintf(want, sizeof want, "ERR webpki_time reject");
        }
        char tlv_hex[2 * WEBPKI_DIFF_TIME_MAX + 2];
        (void)hex_encode(tlv_hex, tlv, tlv_len);
        char cmd[2 * WEBPKI_DIFF_TIME_MAX + 32];
        (void)snprintf(cmd, sizeof cmd, "webpki_time %s", tlv_hex);
        expect(cmd, want);
    }
}

static void diff_webpki_pack(void) {
    static const uint64_t edge[] = {0,
                                    1,
                                    86399,
                                    86400,
                                    951782400,
                                    4102444800,
                                    WEBPKI_DIFF_SECONDS_MAX - 1,
                                    WEBPKI_DIFF_SECONDS_MAX,
                                    WEBPKI_DIFF_SECONDS_MAX + 1,
                                    UINT64_MAX};
    for (int i = 0; i < 300; i++) {
        uint64_t seconds = 0;
        if ((size_t)i < sizeof edge / sizeof edge[0]) {
            seconds = edge[i];
        } else if (i % 5 == 4) {
            seconds = rng_next();
        } else {
            seconds = rng_next() % (WEBPKI_DIFF_SECONDS_MAX + 1);
        }
        char want[32];
        (void)snprintf(want, sizeof want, "%llu", (unsigned long long)webpki_pack_seconds(seconds));
        char cmd[64];
        (void)snprintf(cmd, sizeof cmd, "webpki_pack %llu", (unsigned long long)seconds);
        expect(cmd, want);
    }
}

// How many rows of each name section the C side accepted: the count
// is printed so a run shows both verdicts were compared, not only
// refusals.
static long webpki_diff_hostnames_ok;
static long webpki_diff_san_matches;

static void diff_webpki_hostname(void) {
    for (int i = 0; i < 800; i++) {
        uint8_t host[WEBPKI_DIFF_NAME_MAX];
        size_t host_len = rng_below(WEBPKI_DIFF_NAME_MAX + 1);
        webpki_diff_name(host, host_len);
        int ok = webpki_hostname_ok(host, host_len);
        webpki_diff_hostnames_ok += ok;
        const char *want = ok ? "1" : "0";
        char host_hex[2 * WEBPKI_DIFF_NAME_MAX + 2];
        (void)hex_encode(host_hex, host, host_len);
        char cmd[2 * WEBPKI_DIFF_NAME_MAX + 32];
        (void)snprintf(cmd, sizeof cmd, "webpki_hostname %s", host_hex);
        expect(cmd, want);
    }
}

// A host derived from a presented name: the name with each letter's
// case flipped at random, or, when the name starts with "*.", a
// fresh one-to-three byte label in the wildcard's place.
static size_t webpki_diff_derive_host(const uint8_t *name, size_t name_len, uint8_t *host) {
    if (name_len >= 2 && name[0] == '*' && name[1] == '.' && rng_below(2) == 0) {
        size_t label_len = 1 + rng_below(3);
        webpki_diff_name(host, label_len);
        size_t rest = name_len - 1;
        if (label_len + rest > WEBPKI_DIFF_NAME_MAX) {
            rest = WEBPKI_DIFF_NAME_MAX - label_len;
        }
        memcpy(host + label_len, name + 1, rest);
        return label_len + rest;
    }
    for (size_t i = 0; i < name_len; i++) {
        uint8_t c = name[i];
        if (rng_below(2) == 0) {
            if (c == 'a') {
                c = 'A';
            } else if (c == 'A') {
                c = 'a';
            }
        }
        host[i] = c;
    }
    return name_len;
}

// One GeneralName entry's tag: dNSName on six draws in ten; otherwise
// one of the other eight GeneralName tags, a first byte of the
// high-tag-number form (low five bits 0x1f, X.690 §8.1.2.4), the
// dNSName number with the constructed bit set, or any byte at all.
// The last three refuse the whole GeneralNames on both sides, and a
// high-tag-number entry before a matching dNSName is the row that
// tells a one-byte tag reader from a checked one.
static uint8_t webpki_diff_tag(void) {
    static const uint8_t other[] = {0xa0, 0x81, 0xa3, 0xa4, 0xa5, 0x86, 0x87, 0x88};
    switch (rng_below(10)) {
    case 6:
        return other[rng_below(sizeof other)];
    case 7:
        return (uint8_t)(rng_next() | 0x1f);
    case 8:
        return 0xa2;
    case 9:
        return (uint8_t)rng_next();
    default:
        return 0x82;
    }
}

// Builds a GeneralNames of one to three entries into san and picks
// the host: derived from one entry's name on half the rows, drawn
// fresh on the rest. Returns the GeneralNames length.
static size_t webpki_diff_build_san(uint8_t *san, uint8_t *host, size_t *host_len) {
    size_t n = 2;
    size_t entry_count = 1 + rng_below(3);
    size_t host_from = rng_below(entry_count);
    *host_len = 0;
    for (size_t e = 0; e < entry_count; e++) {
        size_t name_len = rng_below(WEBPKI_DIFF_NAME_MAX + 1);
        san[n] = webpki_diff_tag();
        san[n + 1] = (uint8_t)name_len;
        webpki_diff_name(san + n + 2, name_len);
        if (e == host_from && rng_below(2) == 0) {
            *host_len = webpki_diff_derive_host(san + n + 2, name_len, host);
        } else if (e == host_from) {
            *host_len = rng_below(WEBPKI_DIFF_NAME_MAX + 1);
            webpki_diff_name(host, *host_len);
        }
        n += 2 + name_len;
    }
    san[0] = 0x30;
    san[1] = (uint8_t)(n - 2);
    return n;
}

// One row in six is damaged after building, a byte anywhere; and one
// in twelve loses or gains a trailing byte. Returns the new length.
static size_t webpki_diff_damage_san(uint8_t *san, size_t n) {
    if (rng_below(6) == 0) {
        san[rng_below(n)] = (uint8_t)rng_next();
    }
    if (rng_below(12) == 0) {
        rng_fill(san + n, 1);
        n = rng_below(2) ? n - 1 : n + 1;
    }
    return n;
}

// A fixed row first: 9f 1f 2b is one high-tag-number header, tag
// number 31 and length 43, whose content is 30 'A' and then bytes
// shaped like a dNSName entry for victim.test. Read as tag 9f and
// length 1f, that dNSName is an entry of its own and matches. The row
// requires 0 from both sides, not only the same answer.
static void diff_webpki_san_hidden_entry(void) {
    uint8_t san[48] = {0x30, 0x2e, 0x9f, 0x1f, 0x2b};
    memset(san + 5, 'A', 30);
    san[35] = 0x82;
    san[36] = 11;
    memcpy(san + 37, "victim.test", 11);
    static const uint8_t host[] = "victim.test";
    if (webpki_match_san(san, sizeof san, host, 11) != 0) {
        die("webpki_match_san matched a dNSName inside a high-tag-number entry");
    }
    char san_hex[2 * sizeof san + 2];
    (void)hex_encode(san_hex, san, sizeof san);
    char host_hex[2 * sizeof host];
    (void)hex_encode(host_hex, host, 11);
    char cmd[2 * sizeof san + sizeof host_hex + 32];
    (void)snprintf(cmd, sizeof cmd, "webpki_san %s %s", san_hex, host_hex);
    expect(cmd, "0");
}

static void diff_webpki_san(void) {
    diff_webpki_san_hidden_entry();
    for (int i = 0; i < 1000; i++) {
        uint8_t san[WEBPKI_DIFF_SAN_MAX];
        uint8_t host[WEBPKI_DIFF_NAME_MAX];
        size_t host_len = 0;
        size_t n = webpki_diff_build_san(san, host, &host_len);
        n = webpki_diff_damage_san(san, n);
        int matched = webpki_match_san(san, n, host, host_len);
        webpki_diff_san_matches += matched;
        const char *want = matched ? "1" : "0";
        char san_hex[2 * WEBPKI_DIFF_SAN_MAX + 2];
        (void)hex_encode(san_hex, san, n);
        char host_hex[2 * WEBPKI_DIFF_NAME_MAX + 2];
        (void)hex_encode(host_hex, host, host_len);
        char cmd[2 * WEBPKI_DIFF_SAN_MAX + 2 * WEBPKI_DIFF_NAME_MAX + 32];
        (void)snprintf(cmd, sizeof cmd, "webpki_san %s %s", san_hex, host_hex);
        expect(cmd, want);
    }
    (void)printf(
        "diff: webpki: %ld of 800 hostnames accepted, %ld of 1000 subjectAltNames matched, "
        "C == spec\n",
        webpki_diff_hostnames_ok, webpki_diff_san_matches);
}

#endif
