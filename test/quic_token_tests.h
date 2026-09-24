// quic_token.c: the round trip, the layout, the tamper sweep, the window and
// the boundary pairs. It uses CHECK from test/srv_quic_test.c and is included
// after it.
//
// No standard prints a token: RFC 9000 §8.1.4 leaves the format to the server
// that mints and checks it (rfc9000.txt:2442-2443). So the cases here check the
// claims quic_token.h makes instead. A minted token checks back to what it
// carried. Its bytes are the ones the header's layout names, built here by
// hand. A token whose bytes, key or address changed does not check, and every
// length and instant rule holds at its exact boundary. HMAC-SHA-256 itself is
// checked against RFC 4231 in test/unit_test.c, so nothing here re-checks it.
#ifndef CH_QUIC_TOKEN_TESTS_H
#define CH_QUIC_TOKEN_TESTS_H

#include <string.h>

#include "hkdf.h"
#include "quic_token.h"

// The key the cases mint under, and a second key that differs in one byte.
static const uint8_t token_key[CH_QUIC_TOKEN_KEY_LEN] = {
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
    0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88, 0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x00};
static const uint8_t token_other_key[CH_QUIC_TOKEN_KEY_LEN] = {
    0x11, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
    0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79, 0x88, 0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1, 0x00};

// Two client addresses, each an address and a port: 2001:db8::1 port 4433,
// the longest the token binds, and 192.0.2.1 port 4433. The last byte of
// each is the port's low byte.
static const uint8_t address_v6[CH_QUIC_TOKEN_ADDRESS_MAX] = {0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00,
                                                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                              0x00, 0x00, 0x00, 0x01, 0x11, 0x51};
static const uint8_t address_v4[6] = {192, 0, 2, 1, 0x11, 0x51};

// The label the tag covers first, as quic_token.h prints it. The test keeps
// its own copy, so a label changed in quic_token.c alone fails the layout
// case.
static const char token_label_text[] = "chapulin quic token";

// The instant and the lifetime most cases use, in seconds.
#define TOKEN_ISSUED 1790000000u
#define TOKEN_LIFETIME 10u

// A token one byte longer than any the mint writes, for the cases that build
// one that is too long.
#define TOKEN_BUF (CH_QUIC_TOKEN_MAX + 1)

// The two connection IDs at the lengths given, in counting patterns, so a
// byte written at the wrong offset shows as the wrong value.
static ch_quic_retry_cids token_cids(uint8_t original_dcid_len, uint8_t retry_scid_len) {
    ch_quic_retry_cids cids;
    memset(&cids, 0, sizeof cids);
    for (uint8_t i = 0; i < original_dcid_len && i < CH_QUIC_DCID_MAX; i++) {
        cids.original_dcid[i] = (uint8_t)(0x40 + i);
    }
    for (uint8_t i = 0; i < retry_scid_len && i < CH_QUIC_DCID_MAX; i++) {
        cids.retry_scid[i] = (uint8_t)(0x80 + i);
    }
    cids.original_dcid_len = original_dcid_len;
    cids.retry_scid_len = retry_scid_len;
    return cids;
}

// Whether every byte of *cids still holds the 0xa5 the check cases write
// before each call.
static int cids_untouched(const ch_quic_retry_cids *cids) {
    const uint8_t *p = (const uint8_t *)cids;
    for (size_t i = 0; i < sizeof *cids; i++) {
        if (p[i] != 0xa5) {
            return 0;
        }
    }
    return 1;
}

// Whether two connection ID pairs hold the same lengths and the same bytes.
static int cids_equal(const ch_quic_retry_cids *a, const ch_quic_retry_cids *b) {
    return a->original_dcid_len == b->original_dcid_len && a->retry_scid_len == b->retry_scid_len &&
           memcmp(a->original_dcid, b->original_dcid, a->original_dcid_len) == 0 &&
           memcmp(a->retry_scid, b->retry_scid, a->retry_scid_len) == 0;
}

// Mints one token under token_key into dst and returns its length, or 0 when
// the mint refused.
static size_t token_mint(uint8_t *dst, size_t cap, const uint8_t *address, size_t address_len,
                         const ch_quic_retry_cids *cids, uint64_t issued) {
    size_t n = 0;
    int rc = ch_srv_quic_token_mint(token_key, address, address_len, cids, issued, dst, cap, &n);
    return rc == CH_OK ? n : 0;
}

// Checks n token bytes under token_key and returns the code. Every refusal
// must leave *got as it was, so each call starts from 0xa5 bytes and a
// refusal is checked against them here.
static int token_check(const uint8_t *token, size_t n, const uint8_t *address, size_t address_len,
                       uint64_t now, uint64_t lifetime, ch_quic_retry_cids *got) {
    memset(got, 0xa5, sizeof *got);
    int rc = ch_srv_quic_token_check(token_key, token, n, address, address_len, now, lifetime, got);
    if (rc != CH_OK) {
        CHECK(cids_untouched(got));
    }
    return rc;
}

// The same check, for the cases that read only the code: the v6 address and
// the default lifetime.
static int token_check_v6(const uint8_t *token, size_t n, uint64_t now) {
    ch_quic_retry_cids got;
    return token_check(token, n, address_v6, sizeof address_v6, now, TOKEN_LIFETIME, &got);
}

// Builds a token by hand from the layout quic_token.h prints, with a valid
// tag under token_key over address_v6, and returns its length. The type and
// the two lengths are the caller's, so a case can build a token the mint
// never writes: one of another type, or one whose connection ID is longer
// than CH_QUIC_DCID_MAX. dst takes TOKEN_BUF bytes.
static size_t hand_token(uint8_t type, uint64_t issued, size_t original_dcid_len,
                         size_t retry_scid_len, uint8_t *dst) {
    size_t off = 0;
    dst[off++] = type;
    for (int shift = 56; shift >= 0; shift -= 8) {
        dst[off++] = (uint8_t)(issued >> shift);
    }
    dst[off++] = (uint8_t)original_dcid_len;
    for (size_t i = 0; i < original_dcid_len; i++) {
        dst[off++] = (uint8_t)(0x40 + i);
    }
    dst[off++] = (uint8_t)retry_scid_len;
    for (size_t i = 0; i < retry_scid_len; i++) {
        dst[off++] = (uint8_t)(0x80 + i);
    }

    // The tag input: the label, the address length byte, the address and the
    // body, which is everything written above.
    uint8_t input[sizeof token_label_text + 1 + CH_QUIC_TOKEN_ADDRESS_MAX + TOKEN_BUF];
    size_t in = sizeof token_label_text - 1;
    memcpy(input, token_label_text, in);
    input[in++] = (uint8_t)sizeof address_v6;
    memcpy(input + in, address_v6, sizeof address_v6);
    in += sizeof address_v6;
    memcpy(input + in, dst, off);
    in += off;
    hmac_sha256(token_key, sizeof token_key, input, in, dst + off);
    return off + SHA256_LEN;
}

static void test_token_round_trip(void) {
    // The shortest token at the shortest address, the longest at the longest,
    // and one between, each checked back to what it carried.
    static const struct {
        uint8_t original_dcid_len;
        uint8_t retry_scid_len;
        size_t address_len;
    } shapes[] = {
        {0,                0,                1                        },
        {0,                0,                sizeof address_v4        },
        {8,                20,               sizeof address_v6        },
        {CH_QUIC_DCID_MAX, CH_QUIC_DCID_MAX, CH_QUIC_TOKEN_ADDRESS_MAX}
    };
    for (size_t s = 0; s < sizeof shapes / sizeof shapes[0]; s++) {
        ch_quic_retry_cids cids = token_cids(shapes[s].original_dcid_len, shapes[s].retry_scid_len);
        const uint8_t *address =
            shapes[s].address_len == sizeof address_v4 ? address_v4 : address_v6;
        uint8_t token[CH_QUIC_TOKEN_MAX];
        size_t n =
            token_mint(token, sizeof token, address, shapes[s].address_len, &cids, TOKEN_ISSUED);
        CHECK(n == 43u + shapes[s].original_dcid_len + shapes[s].retry_scid_len);
        ch_quic_retry_cids got;
        CHECK(token_check(token, n, address, shapes[s].address_len, TOKEN_ISSUED, TOKEN_LIFETIME,
                          &got) == CH_OK);
        CHECK(cids_equal(&got, &cids));
    }

    // The longest token is CH_QUIC_TOKEN_MAX bytes and the shortest 43.
    ch_quic_retry_cids longest = token_cids(CH_QUIC_DCID_MAX, CH_QUIC_DCID_MAX);
    uint8_t token[CH_QUIC_TOKEN_MAX];
    size_t n =
        token_mint(token, sizeof token, address_v6, sizeof address_v6, &longest, TOKEN_ISSUED);
    CHECK(n == CH_QUIC_TOKEN_MAX);

    // The mint draws no randomness, so two mints of one input are the same
    // bytes, which is what lets a seeded simulation replay a token.
    uint8_t again[CH_QUIC_TOKEN_MAX];
    CHECK(token_mint(again, sizeof again, address_v6, sizeof address_v6, &longest, TOKEN_ISSUED) ==
          n);
    CHECK(memcmp(again, token, n) == 0);

    // A different key mints different bytes, and neither key checks the
    // other's token.
    size_t other = 0;
    CHECK(ch_srv_quic_token_mint(token_other_key, address_v6, sizeof address_v6, &longest,
                                 TOKEN_ISSUED, again, sizeof again, &other) == CH_OK);
    CHECK(other == n);
    CHECK(memcmp(again, token, n) != 0);
    CHECK(token_check_v6(again, other, TOKEN_ISSUED) == CH_EAUTH);
}

static void test_token_layout(void) {
    // The minted bytes are the layout quic_token.h prints, byte by byte, tag
    // included.
    ch_quic_retry_cids cids = token_cids(8, 20);
    uint8_t token[CH_QUIC_TOKEN_MAX];
    size_t n = token_mint(token, sizeof token, address_v6, sizeof address_v6, &cids, TOKEN_ISSUED);
    uint8_t want[TOKEN_BUF];
    size_t want_len = hand_token(QUIC_TOKEN_TYPE_RETRY, TOKEN_ISSUED, 8, 20, want);
    CHECK(n == want_len);
    CHECK(memcmp(token, want, want_len) == 0);

    // The issue instant is eight bytes, the most significant first.
    static const uint8_t want_instant[8] = {0x00, 0x00, 0x00, 0x00, 0x6a, 0xb1, 0x3b, 0x80};
    CHECK(memcmp(token + 1, want_instant, sizeof want_instant) == 0);
}

static void test_token_address_and_key(void) {
    ch_quic_retry_cids cids = token_cids(8, 8);
    uint8_t token[CH_QUIC_TOKEN_MAX];
    size_t n = token_mint(token, sizeof token, address_v6, sizeof address_v6, &cids, TOKEN_ISSUED);
    ch_quic_retry_cids got;

    // Another port at the same address, another address at the same length,
    // and another address of another length: none of them checks.
    uint8_t moved[CH_QUIC_TOKEN_ADDRESS_MAX];
    memcpy(moved, address_v6, sizeof moved);
    moved[sizeof moved - 1] ^= 0x01;
    CHECK(token_check(token, n, moved, sizeof moved, TOKEN_ISSUED, TOKEN_LIFETIME, &got) ==
          CH_EAUTH);
    memcpy(moved, address_v6, sizeof moved);
    moved[0] ^= 0x80;
    CHECK(token_check(token, n, moved, sizeof moved, TOKEN_ISSUED, TOKEN_LIFETIME, &got) ==
          CH_EAUTH);
    CHECK(token_check(token, n, address_v4, sizeof address_v4, TOKEN_ISSUED, TOKEN_LIFETIME,
                      &got) == CH_EAUTH);
    // The address's first six bytes are not the address either: the length
    // byte is under the tag.
    CHECK(token_check(token, n, address_v6, 6, TOKEN_ISSUED, TOKEN_LIFETIME, &got) == CH_EAUTH);

    // Another key does not check it.
    memset(&got, 0xa5, sizeof got);
    CHECK(ch_srv_quic_token_check(token_other_key, token, n, address_v6, sizeof address_v6,
                                  TOKEN_ISSUED, TOKEN_LIFETIME, &got) == CH_EAUTH);
    CHECK(cids_untouched(&got));
}

static void test_token_tamper(void) {
    ch_quic_retry_cids cids = token_cids(CH_QUIC_DCID_MAX, CH_QUIC_DCID_MAX);
    uint8_t good[CH_QUIC_TOKEN_MAX];
    size_t n = token_mint(good, sizeof good, address_v6, sizeof address_v6, &cids, TOKEN_ISSUED);
    CHECK(n == sizeof good);
    CHECK(token_check_v6(good, n, TOKEN_ISSUED) == CH_OK);

    // Every byte is under the tag, or is the tag. Flipping one bit of any of
    // them refuses the token. At byte 0 the flip makes the type 0x00, which
    // is not a Retry token at all; everywhere else it is a Retry token that
    // does not verify.
    for (size_t i = 0; i < n; i++) {
        uint8_t bad[CH_QUIC_TOKEN_MAX];
        memcpy(bad, good, n);
        bad[i] ^= 0x01;
        CHECK(token_check_v6(bad, n, TOKEN_ISSUED) == (i == 0 ? CH_EPROTO : CH_EAUTH));
    }
}

static void test_token_lengths(void) {
    ch_quic_retry_cids cids = token_cids(CH_QUIC_DCID_MAX, CH_QUIC_DCID_MAX);
    uint8_t good[TOKEN_BUF];
    size_t n =
        token_mint(good, CH_QUIC_TOKEN_MAX, address_v6, sizeof address_v6, &cids, TOKEN_ISSUED);
    CHECK(n == CH_QUIC_TOKEN_MAX);

    // Every truncation is refused by the reader rather than by a read past
    // its end: from one byte, which holds the type alone, to one byte short.
    for (size_t len = 1; len < n; len++) {
        CHECK(token_check_v6(good, len, TOKEN_ISSUED) == CH_EAUTH);
    }

    // One byte too many is refused as well, which makes this one longer
    // than CH_QUIC_TOKEN_MAX.
    good[n] = 0x00;
    CHECK(token_check_v6(good, n + 1, TOKEN_ISSUED) == CH_EAUTH);

    // A zero-length token is no Retry token.
    CHECK(token_check_v6(good, 0, TOKEN_ISSUED) == CH_EPROTO);

    // A connection ID one byte past CH_QUIC_DCID_MAX is refused even under a
    // valid tag, because *cids has no room for it.
    uint8_t wide[TOKEN_BUF];
    size_t wide_len =
        hand_token(QUIC_TOKEN_TYPE_RETRY, TOKEN_ISSUED, CH_QUIC_DCID_MAX + 1, 0, wide);
    CHECK(token_check_v6(wide, wide_len, TOKEN_ISSUED) == CH_EAUTH);
    wide_len = hand_token(QUIC_TOKEN_TYPE_RETRY, TOKEN_ISSUED, 0, CH_QUIC_DCID_MAX + 1, wide);
    CHECK(token_check_v6(wide, wide_len, TOKEN_ISSUED) == CH_EAUTH);
    // At the cap itself the same hand-built token checks, so the two cases
    // above are refused for their length and not for how they were built.
    wide_len = hand_token(QUIC_TOKEN_TYPE_RETRY, TOKEN_ISSUED, CH_QUIC_DCID_MAX, 0, wide);
    CHECK(token_check_v6(wide, wide_len, TOKEN_ISSUED) == CH_OK);
}

static void test_token_type(void) {
    // A NEW_TOKEN token is refused even when its tag verifies: this build
    // mints none, and RFC 9000 §8.1.1 makes the two kinds need different
    // handling (rfc9000.txt:2263-2266).
    uint8_t token[TOKEN_BUF];
    size_t n = hand_token(QUIC_TOKEN_TYPE_NEW_TOKEN, TOKEN_ISSUED, 8, 8, token);
    CHECK(token_check_v6(token, n, TOKEN_ISSUED) == CH_EPROTO);

    // So is any other first byte.
    static const uint8_t types[] = {0x00, 0x03, 0xff};
    for (size_t i = 0; i < sizeof types; i++) {
        n = hand_token(types[i], TOKEN_ISSUED, 8, 8, token);
        CHECK(token_check_v6(token, n, TOKEN_ISSUED) == CH_EPROTO);
    }

    // The same bytes under the Retry type check.
    n = hand_token(QUIC_TOKEN_TYPE_RETRY, TOKEN_ISSUED, 8, 8, token);
    CHECK(token_check_v6(token, n, TOKEN_ISSUED) == CH_OK);
}

// Mints the shortest token at issued and checks it at now under lifetime.
static int token_window(uint64_t issued, uint64_t now, uint64_t lifetime) {
    ch_quic_retry_cids cids = token_cids(0, 0);
    uint8_t token[CH_QUIC_TOKEN_MAX];
    size_t n = token_mint(token, sizeof token, address_v6, sizeof address_v6, &cids, issued);
    ch_quic_retry_cids got;
    return token_check(token, n, address_v6, sizeof address_v6, now, lifetime, &got);
}

static void test_token_window(void) {
    // The last valid instant checks and the first invalid one does not, at
    // both ends: now equal to issued, and now lifetime seconds after it.
    CHECK(token_window(TOKEN_ISSUED, TOKEN_ISSUED, TOKEN_LIFETIME) == CH_OK);
    CHECK(token_window(TOKEN_ISSUED, TOKEN_ISSUED + TOKEN_LIFETIME, TOKEN_LIFETIME) == CH_OK);
    CHECK(token_window(TOKEN_ISSUED, TOKEN_ISSUED + TOKEN_LIFETIME + 1, TOKEN_LIFETIME) ==
          CH_EAUTH);
    // A token issued one second after now is refused.
    CHECK(token_window(TOKEN_ISSUED, TOKEN_ISSUED - 1, TOKEN_LIFETIME) == CH_EAUTH);

    // A lifetime of 0 admits the issuing second alone.
    CHECK(token_window(TOKEN_ISSUED, TOKEN_ISSUED, 0) == CH_OK);
    CHECK(token_window(TOKEN_ISSUED, TOKEN_ISSUED + 1, 0) == CH_EAUTH);

    // The ends of uint64_t. The widest window admits every instant from 0 to
    // UINT64_MAX, and a token issued one second after now is still refused
    // under it: a check that subtracted first would wrap to UINT64_MAX and
    // accept it.
    CHECK(token_window(UINT64_MAX, UINT64_MAX, 0) == CH_OK);
    CHECK(token_window(0, UINT64_MAX, UINT64_MAX) == CH_OK);
    CHECK(token_window(1, 0, UINT64_MAX) == CH_EAUTH);
    CHECK(token_window(UINT64_MAX, UINT64_MAX - 1, UINT64_MAX) == CH_EAUTH);
}

static void test_token_mint_refusals(void) {
    ch_quic_retry_cids cids = token_cids(8, 8);
    uint8_t address[CH_QUIC_TOKEN_ADDRESS_MAX + 1];
    memset(address, 0x33, sizeof address);
    uint8_t token[TOKEN_BUF];
    size_t n = 0x5a5a;

    // The address length pair at both ends: 0 and one past the cap are
    // refused, 1 and the cap are minted.
    CHECK(ch_srv_quic_token_mint(token_key, address, 0, &cids, TOKEN_ISSUED, token, sizeof token,
                                 &n) == CH_EINVAL);
    CHECK(ch_srv_quic_token_mint(token_key, address, CH_QUIC_TOKEN_ADDRESS_MAX + 1, &cids,
                                 TOKEN_ISSUED, token, sizeof token, &n) == CH_EINVAL);
    CHECK(n == 0x5a5a);
    CHECK(token_mint(token, sizeof token, address, 1, &cids, TOKEN_ISSUED) == 59);
    CHECK(token_mint(token, sizeof token, address, CH_QUIC_TOKEN_ADDRESS_MAX, &cids,
                     TOKEN_ISSUED) == 59);

    // Each connection ID length at the cap and one past it.
    ch_quic_retry_cids wide = token_cids(CH_QUIC_DCID_MAX + 1, 0);
    CHECK(ch_srv_quic_token_mint(token_key, address, 6, &wide, TOKEN_ISSUED, token, sizeof token,
                                 &n) == CH_EINVAL);
    wide = token_cids(0, CH_QUIC_DCID_MAX + 1);
    CHECK(ch_srv_quic_token_mint(token_key, address, 6, &wide, TOKEN_ISSUED, token, sizeof token,
                                 &n) == CH_EINVAL);
    CHECK(n == 0x5a5a);
    wide = token_cids(CH_QUIC_DCID_MAX, 0);
    CHECK(token_mint(token, sizeof token, address, 6, &wide, TOKEN_ISSUED) == 63);

    // The capacity pair: the token's own length works, and one byte below
    // it writes nothing, not even *out_len.
    uint8_t probe[TOKEN_BUF];
    memset(probe, 0xa5, sizeof probe);
    CHECK(ch_srv_quic_token_mint(token_key, address, 6, &cids, TOKEN_ISSUED, probe, 58, &n) ==
          CH_ECAP);
    CHECK(n == 0x5a5a);
    for (size_t i = 0; i < sizeof probe; i++) {
        CHECK(probe[i] == 0xa5);
    }
    CHECK(token_mint(probe, 59, address, 6, &cids, TOKEN_ISSUED) == 59);
}

static void test_token_check_refusals(void) {
    ch_quic_retry_cids cids = token_cids(8, 8);
    uint8_t token[CH_QUIC_TOKEN_MAX];
    size_t n = token_mint(token, sizeof token, address_v6, sizeof address_v6, &cids, TOKEN_ISSUED);
    ch_quic_retry_cids got;

    // The caller's address length pair: 0 and one past the cap are the
    // caller's error, whatever the token holds.
    uint8_t address[CH_QUIC_TOKEN_ADDRESS_MAX + 1];
    memcpy(address, address_v6, sizeof address_v6);
    address[CH_QUIC_TOKEN_ADDRESS_MAX] = 0x00;
    CHECK(token_check(token, n, address, 0, TOKEN_ISSUED, TOKEN_LIFETIME, &got) == CH_EINVAL);
    CHECK(token_check(token, n, address, CH_QUIC_TOKEN_ADDRESS_MAX + 1, TOKEN_ISSUED,
                      TOKEN_LIFETIME, &got) == CH_EINVAL);
    CHECK(token_check(token, n, address, CH_QUIC_TOKEN_ADDRESS_MAX, TOKEN_ISSUED, TOKEN_LIFETIME,
                      &got) == CH_OK);
}

static void test_quic_token(void) {
    test_token_round_trip();
    test_token_layout();
    test_token_address_and_key();
    test_token_tamper();
    test_token_lengths();
    test_token_type();
    test_token_window();
    test_token_mint_refusals();
    test_token_check_refusals();
}

#endif
