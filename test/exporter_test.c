// The exporter of RFC 9846 §7.5, both halves: ks_exporter's arithmetic
// against fixed vectors, and ch_export's refusals against a session the
// test builds by hand. Built as bin/exporter_test with EXPORTER=on's
// defines, because the default object carries neither.
//
// Where the vectors come from, and what that is worth. RFC 9846 prints
// no exporter vector and neither does RFC 8448's trace, so there is no
// published answer to check against. These four were produced by this
// code and confirmed byte for byte against an independent implementation
// written from §7.5's text in Python, over the same inputs. That catches
// a misread of the spec, which is what a published vector would catch.
// It does not catch a shared misreading, so the README says these are
// cross-checked rather than published.
//
// The inputs are counters rather than a real handshake's secrets: this
// binary tests the derivation. bin/tcp_nonblocking_loop_test is built
// with the same axis and is where a real session runs it: a client and
// a server that completed one handshake export one secret.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "keysched.h"
#include "rand.h"
#include "tls.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

void ch_rand_bytes(uint8_t *p, size_t n) {
    memset(p, 0, n);
}

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

static int hex_eq(const uint8_t *got, const char *want_hex, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int hi = hex_nibble(want_hex[2 * i]);
        int lo = hex_nibble(want_hex[2 * i + 1]);
        if (hi < 0 || lo < 0 || got[i] != (uint8_t)((hi << 4) | lo)) {
            return 0;
        }
    }
    return 1;
}

// master and the CH..server-Finished transcript hash, as counters.
static void fixed_inputs(uint8_t master[SHA256_LEN], uint8_t transcript[SHA256_LEN]) {
    for (size_t i = 0; i < SHA256_LEN; i++) {
        master[i] = (uint8_t)i;
        transcript[i] = (uint8_t)(0x40 + i);
    }
}

static void test_vectors(void) {
    uint8_t master[SHA256_LEN];
    uint8_t transcript[SHA256_LEN];
    uint8_t exp_master[SHA256_LEN];
    fixed_inputs(master, transcript);

    ks_exp_master(SHA256_LEN, master, transcript, exp_master);
    CHECK(hex_eq(exp_master, "61bab2e46006de1948b2e8e1b8661e9636e6034449a3734baf180be9732164a3",
                 SHA256_LEN));

    // RFC 9266's label, which is 24 bytes and the reason this axis raises
    // HKDF_LABEL_MAX past the 12 TLS 1.3's own labels need.
    uint8_t out[SHA256_LEN];
    ks_exporter(SHA256_LEN, exp_master, "EXPORTER-Channel-Binding", NULL, 0, out, sizeof out);
    CHECK(hex_eq(out, "bf20dc7b67314ed4d32b7f375dbdb9c442bbffb92734b629d7ef70c457cf0e73",
                 sizeof out));

    static const uint8_t context[5] = {'h', 'e', 'l', 'l', 'o'};
    ks_exporter(SHA256_LEN, exp_master, "EXPORTER-Channel-Binding", context, sizeof context, out,
                sizeof out);
    CHECK(hex_eq(out, "2fd00edd8b0265b9e784262b78d641ced8aa58050c2a91d03aaece563b48d665",
                 sizeof out));

    // A short label and a short output, so neither length is fixed by
    // the vectors above.
    uint8_t out16[16];
    ks_exporter(SHA256_LEN, exp_master, "exp", context, sizeof context, out16, sizeof out16);
    CHECK(hex_eq(out16, "e04d4785f4ff079237b84288fa3867f9", sizeof out16));
}

// The two things a caller relies on: one label gives one answer however
// often it asks, and two labels give unrelated answers from the one
// session.
static void test_label_separation(void) {
    uint8_t master[SHA256_LEN];
    uint8_t transcript[SHA256_LEN];
    uint8_t exp_master[SHA256_LEN];
    fixed_inputs(master, transcript);
    ks_exp_master(SHA256_LEN, master, transcript, exp_master);

    uint8_t first[SHA256_LEN];
    uint8_t again[SHA256_LEN];
    uint8_t other[SHA256_LEN];
    ks_exporter(SHA256_LEN, exp_master, "label-one", NULL, 0, first, sizeof first);
    ks_exporter(SHA256_LEN, exp_master, "label-one", NULL, 0, again, sizeof again);
    ks_exporter(SHA256_LEN, exp_master, "label-two", NULL, 0, other, sizeof other);
    CHECK(memcmp(first, again, sizeof first) == 0);
    CHECK(memcmp(first, other, sizeof first) != 0);

    // The context separates as the label does.
    static const uint8_t context[1] = {0};
    uint8_t with_context[SHA256_LEN];
    ks_exporter(SHA256_LEN, exp_master, "label-one", context, sizeof context, with_context,
                sizeof with_context);
    CHECK(memcmp(first, with_context, sizeof first) != 0);
}

// ch_export reads the session and validates the caller's arguments. The
// session is built by hand because this binary runs no handshake: the
// call reads t.state and t.exp_master and nothing else.
static void test_public_refusals(void) {
    ch_tls t;
    memset(&t, 0, sizeof t);
    uint8_t transcript[SHA256_LEN];
    uint8_t master[SHA256_LEN];
    fixed_inputs(master, transcript);
    ks_exp_master(SHA256_LEN, master, transcript, t.exp_master);

    uint8_t out[32];
    static const uint8_t context[2] = {1, 2};

    // Before CONNECTED the secret is not derived, whatever the struct holds.
    t.state = CH_ST_START;
    CHECK(ch_export(&t, "label", NULL, 0, out, sizeof out) == CH_EINVAL);
    t.state = CH_ST_CLOSED;
    CHECK(ch_export(&t, "label", NULL, 0, out, sizeof out) == CH_EINVAL);
    t.state = CH_ST_FAILED;
    CHECK(ch_export(&t, "label", NULL, 0, out, sizeof out) == CH_EINVAL);

    t.state = CH_ST_CONNECTED;
    CHECK(ch_export(&t, "label", NULL, 0, out, sizeof out) == CH_OK);

    // The argument rules, each one alone.
    CHECK(ch_export(&t, NULL, NULL, 0, out, sizeof out) == CH_EINVAL);
    CHECK(ch_export(&t, "", NULL, 0, out, sizeof out) == CH_EINVAL);
    CHECK(ch_export(&t, "label", NULL, 0, NULL, sizeof out) == CH_EINVAL);
    CHECK(ch_export(&t, "label", NULL, 0, out, 0) == CH_EINVAL);
    CHECK(ch_export(&t, "label", NULL, 3, out, sizeof out) == CH_EINVAL);
    CHECK(ch_export(&t, "label", context, sizeof context, out, sizeof out) == CH_OK);

    // The label boundary, both sides of it.
    char label[CH_EXPORT_LABEL_MAX + 2];
    memset(label, 'x', sizeof label);
    label[CH_EXPORT_LABEL_MAX] = '\0';
    CHECK(ch_export(&t, label, NULL, 0, out, sizeof out) == CH_OK);
    label[CH_EXPORT_LABEL_MAX] = 'x';
    label[CH_EXPORT_LABEL_MAX + 1] = '\0';
    CHECK(ch_export(&t, label, NULL, 0, out, sizeof out) == CH_EINVAL);

    // The output boundary, both sides of it.
    static uint8_t big[CH_EXPORT_MAX + 1];
    CHECK(ch_export(&t, "label", NULL, 0, big, CH_EXPORT_MAX) == CH_OK);
    CHECK(ch_export(&t, "label", NULL, 0, big, CH_EXPORT_MAX + 1) == CH_EINVAL);

    // ch_export answers the same bytes ks_exporter does, so the public
    // call adds validation and nothing else.
    uint8_t direct[SHA256_LEN];
    uint8_t viapublic[SHA256_LEN];
    ks_exporter(SHA256_LEN, t.exp_master, "label", context, sizeof context, direct, sizeof direct);
    CHECK(ch_export(&t, "label", context, sizeof context, viapublic, sizeof viapublic) == CH_OK);
    CHECK(memcmp(direct, viapublic, sizeof direct) == 0);
}

int main(void) {
    test_vectors();
    test_label_separation();
    test_public_refusals();
    if (failures == 0) {
        (void)printf("exporter: vectors, label separation and every refusal\n");
        return 0;
    }
    (void)fprintf(stderr, "exporter: %d failures\n", failures);
    return 1;
}
