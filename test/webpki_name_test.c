// The TRUST=webpki hostname shape check and subjectAltName matcher at
// their boundaries: the 253-byte name and the 63-byte label on both
// sides, every label rule, a hyphen inside a label and at each of its
// edges, the alphabet, the all-digit last label;
// then exact and case-folded matches, the one-label wildcard and each
// shape it refuses, a NUL in a presented name, entries of other
// GeneralName types before the match, the GeneralName tag rule on
// both sides of each edge, lengths in all three DER forms, and each
// malformed GeneralNames shape. Its own binary because only the TRUST=webpki object matches a
// name; the module stays testable without the rest of the stack, the
// way sha512_test does.
#include <stdio.h>
#include <string.h>

#include "webpki.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

static int hostname_ok(const char *host) {
    return webpki_hostname_ok((const uint8_t *)host, strlen(host));
}

// A name of n bytes: labels of 63 'a' separated by dots, cut to n.
static void fill_name(uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        out[i] = (i % 64 == 63) ? '.' : 'a';
    }
}

static void test_hostname_length(void) {
    uint8_t name[CH_HOSTNAME_MAX + 1];
    fill_name(name, sizeof name);
    CHECK(webpki_hostname_ok(name, CH_HOSTNAME_MAX) == 1);
    CHECK(webpki_hostname_ok(name, CH_HOSTNAME_MAX + 1) == 0);
    CHECK(webpki_hostname_ok(name, 0) == 0);
    CHECK(webpki_hostname_ok(name, 1) == 1);
    // A 63-byte label, then the same with one more byte.
    char label[80];
    memset(label, 'b', 63);
    memcpy(label + 63, ".test", 6);
    CHECK(hostname_ok(label) == 1);
    memset(label, 'b', 64);
    memcpy(label + 64, ".test", 6);
    CHECK(hostname_ok(label) == 0);
    // The label rule holds for the last label too.
    memcpy(label, "test.", 5);
    memset(label + 5, 'b', 63);
    label[68] = '\0';
    CHECK(hostname_ok(label) == 1);
    memset(label + 5, 'b', 64);
    label[69] = '\0';
    CHECK(hostname_ok(label) == 0);
}

static void test_hostname_labels(void) {
    CHECK(hostname_ok("example.test") == 1);
    CHECK(hostname_ok("localhost") == 1);
    CHECK(hostname_ok("s3.us-east-1.amazonaws.com") == 1);
    CHECK(hostname_ok("Example.TEST") == 1);
    CHECK(hostname_ok("a..b") == 0);
    CHECK(hostname_ok(".example.test") == 0);
    CHECK(hostname_ok("example.test.") == 0);
    CHECK(hostname_ok(".") == 0);
    // An all-digit last label is an IPv4 literal's shape.
    CHECK(hostname_ok("192.0.2.1") == 0);
    CHECK(hostname_ok("a.b.1") == 0);
    CHECK(hostname_ok("123") == 0);
    CHECK(hostname_ok("a.1.b") == 1);
    CHECK(hostname_ok("1a") == 1);
    CHECK(hostname_ok("a1") == 1);
}

// No label starts or ends with '-' (RFC 1123 §2.1): a hyphen inside a
// label passes, and one at either edge of the first, a middle or the
// last label fails.
static void test_hostname_hyphens(void) {
    CHECK(hostname_ok("a-b") == 1);
    CHECK(hostname_ok("xn--abc.example") == 1);
    CHECK(hostname_ok("-") == 0);
    CHECK(hostname_ok("-a") == 0);
    CHECK(hostname_ok("a-") == 0);
    CHECK(hostname_ok("-a.b") == 0);
    CHECK(hostname_ok("a-.b") == 0);
    CHECK(hostname_ok("a.-b") == 0);
    CHECK(hostname_ok("a.b-") == 0);
    CHECK(hostname_ok("-a.b-") == 0);
    CHECK(hostname_ok("a.-b-.c") == 0);
    CHECK(hostname_ok("a.b-c.d") == 1);
    // A 63-byte label of 'a', 61 hyphens and 'a'; then the same length
    // with the last 'a' replaced by a hyphen.
    char label[80];
    label[0] = 'a';
    memset(label + 1, '-', 61);
    memcpy(label + 62, "a.test", 7);
    CHECK(hostname_ok(label) == 1);
    label[62] = '-';
    CHECK(hostname_ok(label) == 0);
}

static void test_hostname_alphabet(void) {
    CHECK(hostname_ok("a_b.test") == 0);
    CHECK(hostname_ok("a*b.test") == 0);
    CHECK(hostname_ok("*.example.test") == 0);
    CHECK(hostname_ok("a b.test") == 0);
    CHECK(hostname_ok("a/b.test") == 0);
    CHECK(hostname_ok("a\x80.test") == 0);
    CHECK(hostname_ok("A-Z.a-z.0-9") == 1);
    static const uint8_t nul_inside[] = {'a', 'b', 0, '.', 't', 'e', 's', 't'};
    CHECK(webpki_hostname_ok(nul_inside, sizeof nul_inside) == 0);
    static const uint8_t nul_at_end[] = {'a', 'b', '.', 't', 'e', 's', 't', 0};
    CHECK(webpki_hostname_ok(nul_at_end, sizeof nul_at_end) == 0);
}

// Builds a GeneralNames TLV from entries: each is one tag byte, a
// length in X.690 §10.1's minimal form and a body. Returns the TLV
// length.
typedef struct {
    uint8_t tag;
    const char *body;
    size_t body_len;
} entry;

// The bytes a minimal DER length of len takes: one below 0x80, two
// below 0x100, three up to 0xffff.
static size_t length_size(size_t len) {
    if (len < 0x80) {
        return 1;
    }
    return len < 0x100 ? 2 : 3;
}

static size_t put_length(uint8_t *out, size_t len) {
    size_t size = length_size(len);
    if (size == 1) {
        out[0] = (uint8_t)len;
    } else if (size == 2) {
        out[0] = 0x81;
        out[1] = (uint8_t)len;
    } else {
        out[0] = 0x82;
        out[1] = (uint8_t)(len >> 8);
        out[2] = (uint8_t)len;
    }
    return size;
}

static size_t build_san(uint8_t *out, const entry *entries, size_t count) {
    size_t content_len = 0;
    for (size_t i = 0; i < count; i++) {
        content_len += 1 + length_size(entries[i].body_len) + entries[i].body_len;
    }
    size_t n = 0;
    out[n++] = 0x30;
    n += put_length(out + n, content_len);
    for (size_t i = 0; i < count; i++) {
        out[n++] = entries[i].tag;
        n += put_length(out + n, entries[i].body_len);
        memcpy(out + n, entries[i].body, entries[i].body_len);
        n += entries[i].body_len;
    }
    return n;
}

#define DNS 0x82
#define RFC822 0x81
#define IP 0x87
#define URI 0x86

// One dNSName against one host.
static int match_one(const char *name, const char *host) {
    uint8_t san[300];
    entry e = {DNS, name, strlen(name)};
    size_t n = build_san(san, &e, 1);
    return webpki_match_san(san, n, (const uint8_t *)host, strlen(host));
}

static void test_match_exact(void) {
    CHECK(match_one("s3.example.test", "s3.example.test") == 1);
    CHECK(match_one("S3.Example.TEST", "s3.example.test") == 1);
    CHECK(match_one("s3.example.test", "S3.EXAMPLE.TEST") == 1);
    CHECK(match_one("s3.example.test", "s3.example.tests") == 0);
    CHECK(match_one("s3.example.tests", "s3.example.test") == 0);
    CHECK(match_one("s4.example.test", "s3.example.test") == 0);
    CHECK(match_one("example.test", "s3.example.test") == 0);
    CHECK(match_one("s3.example.test.", "s3.example.test") == 0);
    CHECK(match_one("", "s3.example.test") == 0);
}

static void test_match_wildcard(void) {
    CHECK(match_one("*.example.test", "s3.example.test") == 1);
    CHECK(match_one("*.EXAMPLE.test", "s3.example.TEST") == 1);
    CHECK(match_one("*.example.test", "example.test") == 0);
    CHECK(match_one("*.example.test", "a.b.example.test") == 0);
    CHECK(match_one("*.example.test", "s3.example.tests") == 0);
    CHECK(match_one("*.example.test", "example") == 0);
    CHECK(match_one("*.example.test", "s3.example.test.") == 0);
    // A partial-label wildcard matches nothing.
    CHECK(match_one("s3*.example.test", "s3.example.test") == 0);
    CHECK(match_one("s3*.example.test", "s3x.example.test") == 0);
    CHECK(match_one("*s3.example.test", "s3.example.test") == 0);
    CHECK(match_one("s3.*.test", "s3.example.test") == 0);
    CHECK(match_one("*", "s3") == 0);
    // Fewer than two labels after the wildcard.
    CHECK(match_one("*.com", "example.com") == 0);
    CHECK(match_one("*.", "example") == 0);
    CHECK(match_one("*.", "") == 0);
    CHECK(match_one("*.a.b", "x.a.b") == 1);
}

// A presented name with an embedded NUL never matches: the host
// holds none, and the compare is over equal-length ranges.
static void test_match_nul(void) {
    static const char evil[] = "s3.example.test\0.evil.test";
    uint8_t san[300];
    entry e = {DNS, evil, sizeof evil - 1};
    size_t n = build_san(san, &e, 1);
    const char *host = "s3.example.test";
    CHECK(webpki_match_san(san, n, (const uint8_t *)host, strlen(host)) == 0);
    static const char wild[] = "*.example.test\0.evil.test";
    entry w = {DNS, wild, sizeof wild - 1};
    n = build_san(san, &w, 1);
    CHECK(webpki_match_san(san, n, (const uint8_t *)host, strlen(host)) == 0);
}

// Other GeneralName types are skipped unread, before and after the
// matching entry, and a non-matching dNSName does not end the walk.
static void test_match_walk(void) {
    uint8_t san[300];
    const char *host = "s3.example.test";
    static const uint8_t ipv4[] = {192, 0, 2, 1};
    entry mixed[] = {
        {IP,     (const char *)ipv4,      4 },
        {RFC822, "admin@example.test",    18},
        {DNS,    "other.example.test",    18},
        {URI,    "https://example.test/", 21},
        {DNS,    "s3.example.test",       15},
        {DNS,    "third.example.test",    18}
    };
    size_t n = build_san(san, mixed, 6);
    CHECK(webpki_match_san(san, n, (const uint8_t *)host, strlen(host)) == 1);
    // The same entries with the matching dNSName as an rfc822Name:
    // only dNSName is matched.
    mixed[4].tag = RFC822;
    n = build_san(san, mixed, 6);
    CHECK(webpki_match_san(san, n, (const uint8_t *)host, strlen(host)) == 0);
    // A directoryName-shaped constructed entry is skipped like any other.
    entry constructed[] = {
        {0xa4, "\x30\x00",        2 },
        {DNS,  "s3.example.test", 15}
    };
    n = build_san(san, constructed, 2);
    CHECK(webpki_match_san(san, n, (const uint8_t *)host, strlen(host)) == 1);
}

// GeneralName's nine tags are skipped before a match; every other tag
// byte refuses the GeneralNames, before a match or after it. At each
// edge the last accepted byte and the first refused one: [8] 0x88 and
// [9] 0x89, the constructed [0] 0xa0 and the primitive 0x80.
static void test_match_tags(void) {
    uint8_t san[300];
    const char *host = "s3.example.test";
    size_t host_len = strlen(host);
    static const uint8_t accepted[] = {0xa0, 0x81, 0x82, 0xa3, 0xa4, 0xa5, 0x86, 0x87, 0x88};
    for (size_t i = 0; i < sizeof accepted; i++) {
        entry before[] = {
            {accepted[i], "",   0 },
            {DNS,         host, 15}
        };
        size_t n = build_san(san, before, 2);
        CHECK(webpki_match_san(san, n, (const uint8_t *)host, host_len) == 1);
    }
    static const uint8_t refused[] = {0x89, 0x80, 0xa2, 0x84, 0x04, 0x00, 0x30, 0x9f, 0xbf, 0x1f};
    for (size_t i = 0; i < sizeof refused; i++) {
        entry before[] = {
            {refused[i], "",   0 },
            {DNS,        host, 15}
        };
        size_t n = build_san(san, before, 2);
        CHECK(webpki_match_san(san, n, (const uint8_t *)host, host_len) == 0);
        entry after[] = {
            {DNS,        host, 15},
            {refused[i], "",   0 }
        };
        n = build_san(san, after, 2);
        CHECK(webpki_match_san(san, n, (const uint8_t *)host, host_len) == 0);
    }
    // 9f 1f 2b is one high-tag-number header: tag number 31, length
    // 43. Its content is 30 'A' and then bytes shaped like a dNSName
    // entry for the host. Read as tag 9f and length 1f, that dNSName
    // would be an entry of its own and would match.
    uint8_t hidden[48] = {0x30, 0x2e, 0x9f, 0x1f, 0x2b};
    memset(hidden + 5, 'A', 30);
    hidden[35] = DNS;
    hidden[36] = 11;
    memcpy(hidden + 37, "victim.test", 11);
    CHECK(webpki_match_san(hidden, sizeof hidden, (const uint8_t *)"victim.test", 11) == 0);
}

// Lengths past the short form: a dNSName and a GeneralNames over 127
// bytes (0x81) and over 255 bytes (0x82), and presented names longer
// than any host, which the length compare refuses before any byte of
// the name is read.
static void test_match_long(void) {
    uint8_t name[CH_WEBPKI_EXT_TLV_MAX];
    uint8_t san[CH_WEBPKI_EXT_TLV_MAX + 8];
    fill_name(name, CH_HOSTNAME_MAX);
    entry one = {DNS, (const char *)name, 200};
    size_t n = build_san(san, &one, 1);
    CHECK(san[1] == 0x81 && san[4] == 0x81);
    CHECK(webpki_match_san(san, n, name, 200) == 1);
    CHECK(webpki_match_san(san, n, name, 199) == 0);
    // The 253-byte host against a presented name of 253 and 254 bytes.
    one.body_len = CH_HOSTNAME_MAX;
    n = build_san(san, &one, 1);
    CHECK(webpki_match_san(san, n, name, CH_HOSTNAME_MAX) == 1);
    fill_name(name, CH_HOSTNAME_MAX + 1);
    one.body_len = CH_HOSTNAME_MAX + 1;
    n = build_san(san, &one, 1);
    CHECK(san[1] == 0x82);
    CHECK(webpki_match_san(san, n, name, CH_HOSTNAME_MAX) == 0);
    // A 1000-byte presented name, exact and under a wildcard, against
    // the 253-byte host that is its prefix.
    fill_name(name, 1000);
    one.body_len = 1000;
    n = build_san(san, &one, 1);
    CHECK(webpki_match_san(san, n, name, CH_HOSTNAME_MAX) == 0);
    name[0] = '*';
    name[1] = '.';
    n = build_san(san, &one, 1);
    CHECK(webpki_match_san(san, n, name + 2, CH_HOSTNAME_MAX) == 0);
    // An iPAddress entry, then a 300-byte URI, then the match, all
    // inside one 0x82-length GeneralNames.
    static const char host[] = "s3.example.test";
    static const uint8_t ipv4[] = {192, 0, 2, 1};
    fill_name(name, 300);
    entry mixed[] = {
        {IP,  (const char *)ipv4, 4  },
        {URI, (const char *)name, 300},
        {DNS, host,               15 }
    };
    n = build_san(san, mixed, 3);
    CHECK(san[1] == 0x82);
    CHECK(webpki_match_san(san, n, (const uint8_t *)host, 15) == 1);
}

// Every malformation is a refusal, wherever it sits.
static void test_match_malformed(void) {
    uint8_t san[300];
    const char *host = "s3.example.test";
    size_t host_len = strlen(host);
    entry one = {DNS, "s3.example.test", 15};
    size_t n = build_san(san, &one, 1);
    // The well-formed baseline, then one break at a time.
    CHECK(webpki_match_san(san, n, (const uint8_t *)host, host_len) == 1);
    CHECK(webpki_match_san(san, 0, (const uint8_t *)host, host_len) == 0);
    CHECK(webpki_match_san(san, 1, (const uint8_t *)host, host_len) == 0);
    CHECK(webpki_match_san(san, n - 1, (const uint8_t *)host, host_len) == 0);
    san[0] = 0x31;
    CHECK(webpki_match_san(san, n, (const uint8_t *)host, host_len) == 0);
    san[0] = 0x30;
    san[1] = (uint8_t)(san[1] - 1);
    CHECK(webpki_match_san(san, n, (const uint8_t *)host, host_len) == 0);
    san[1] = (uint8_t)(san[1] + 2);
    CHECK(webpki_match_san(san, n, (const uint8_t *)host, host_len) == 0);
    san[1] = (uint8_t)(san[1] - 1);
    // The inner length runs past the SEQUENCE.
    san[3] = (uint8_t)(san[3] + 1);
    CHECK(webpki_match_san(san, n, (const uint8_t *)host, host_len) == 0);
    san[3] = (uint8_t)(san[3] - 1);
    // A non-minimal inner length for the same bytes.
    uint8_t long_form[300];
    long_form[0] = 0x30;
    long_form[1] = (uint8_t)(n - 2 + 1);
    long_form[2] = DNS;
    long_form[3] = 0x81;
    long_form[4] = 15;
    memcpy(long_form + 5, host, 15);
    CHECK(webpki_match_san(long_form, n + 1, (const uint8_t *)host, host_len) == 0);
    // An empty GeneralNames, and a SEQUENCE holding one lone tag.
    static const uint8_t empty[] = {0x30, 0x00};
    CHECK(webpki_match_san(empty, sizeof empty, (const uint8_t *)host, host_len) == 0);
    static const uint8_t lone_tag[] = {0x30, 0x01, DNS};
    CHECK(webpki_match_san(lone_tag, sizeof lone_tag, (const uint8_t *)host, host_len) == 0);
    // A match followed by a malformed entry is still a refusal: the
    // whole structure is read.
    entry then_cut[] = {
        {DNS, "s3.example.test", 15},
        {DNS, "x",               1 }
    };
    n = build_san(san, then_cut, 2);
    san[n - 2] = 5;
    CHECK(webpki_match_san(san, n, (const uint8_t *)host, host_len) == 0);
    // Bytes after the SEQUENCE.
    n = build_san(san, &one, 1);
    san[n] = 0x00;
    CHECK(webpki_match_san(san, n + 1, (const uint8_t *)host, host_len) == 0);
}

int main(void) {
    test_hostname_length();
    test_hostname_labels();
    test_hostname_hyphens();
    test_hostname_alphabet();
    test_match_exact();
    test_match_wildcard();
    test_match_nul();
    test_match_walk();
    test_match_tags();
    test_match_long();
    test_match_malformed();
    if (failures == 0) {
        (void)printf("webpki_name: all tests passed\n");
    }
    return failures != 0;
}
