// srv_cookie.c: the round trip, the tamper sweep and the boundary pairs. It
// uses CHECK and out from test/srv_test.c and is included after them.
//
// No standard prints a cookie, because the format is this tree's own
// (docs/server.md, "The cookie"). So the cases here check the three claims
// srv_cookie.h makes instead: a minted cookie opens back to what it carried,
// a cookie whose body or MAC moved by one bit does not open, and the length
// rule holds at its exact boundaries. HMAC-SHA-256 itself is checked against
// RFC 4231 in test/unit_test.c, so nothing here re-checks it.
#ifndef CH_SRV_COOKIE_TESTS_H
#define CH_SRV_COOKIE_TESTS_H

// The cookie length a SHA-256 suite fixes: 1 version byte, 2 suite bytes, 2
// group bytes, 32 bytes of Hash(ClientHello1), 32 bytes of frozen-fields
// digest and 32 bytes of MAC.
#define COOKIE_SHA256_LEN (5 + SHA256_LEN + SHA256_LEN + SHA256_LEN)

// The key the cases mint under, and a second key that differs in one byte.
static const uint8_t mint_key[SRV_COOKIE_KEY_LEN] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0};
static const uint8_t other_key[SRV_COOKIE_KEY_LEN] = {
    0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0};

// The two digests one cookie carries. Counting patterns again, so a term
// written at the wrong offset shows as the wrong byte.
static const uint8_t ch1_hash_in[SHA256_LEN] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f};
static const uint8_t frozen_in[SHA256_LEN] = {
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf};

// Mints one cookie into dst under key, at the SHA-256 length.
static size_t mint(uint8_t *dst, size_t cap, const uint8_t *key) {
    return srv_cookie_mint(key, SUITE_CHACHA20_POLY1305_SHA256, CH_KEX_GROUP, ch1_hash_in,
                           SHA256_LEN, frozen_in, dst, cap);
}

// Opens n bytes at src and discards what it read. The tamper cases care only
// about the verdict.
static int opens(const uint8_t *src, size_t n) {
    uint16_t suite = 0;
    uint16_t group = 0;
    size_t hash_len = 0;
    uint8_t hash[SRV_COOKIE_HASH_MAX];
    uint8_t frozen[SHA256_LEN];
    return srv_cookie_open(mint_key, src, n, &suite, &group, hash, &hash_len, frozen) == CH_OK;
}

static void test_cookie_round_trip(void) {
    size_t n = mint(out, sizeof out, mint_key);
    CHECK(n == COOKIE_SHA256_LEN);

    // The body's head, field by field: the format's own version byte, then
    // the suite and the group, each two bytes in network byte order.
    static const uint8_t want_head[] = {SRV_COOKIE_VERSION, 0x13, 0x03, 0x00, 0x1d};
    CHECK(memcmp(out, want_head, sizeof want_head) == 0);
    CHECK(memcmp(out + 5, ch1_hash_in, SHA256_LEN) == 0);
    CHECK(memcmp(out + 5 + SHA256_LEN, frozen_in, SHA256_LEN) == 0);

    uint16_t suite = 0;
    uint16_t group = 0;
    size_t hash_len = 0;
    uint8_t hash[SRV_COOKIE_HASH_MAX];
    uint8_t frozen[SHA256_LEN];
    memset(hash, 0, sizeof hash);
    memset(frozen, 0, sizeof frozen);
    CHECK(srv_cookie_open(mint_key, out, n, &suite, &group, hash, &hash_len, frozen) == CH_OK);
    CHECK(suite == SUITE_CHACHA20_POLY1305_SHA256);
    CHECK(group == CH_KEX_GROUP);
    CHECK(hash_len == SHA256_LEN);
    CHECK(memcmp(hash, ch1_hash_in, SHA256_LEN) == 0);
    CHECK(memcmp(frozen, frozen_in, SHA256_LEN) == 0);

    // The mint draws no randomness, so two mints of one input are the same
    // bytes. A retried ClientHello therefore gets the cookie it got before.
    uint8_t again[COOKIE_SHA256_LEN];
    CHECK(mint(again, sizeof again, mint_key) == n);
    CHECK(memcmp(again, out, n) == 0);

    // A different key mints different bytes, and its cookie does not open
    // here.
    CHECK(mint(again, sizeof again, other_key) == n);
    CHECK(memcmp(again, out, n) != 0);
    CHECK(!opens(again, n));
}

static void test_cookie_tamper(void) {
    uint8_t good[COOKIE_SHA256_LEN];
    size_t n = mint(good, sizeof good, mint_key);
    CHECK(n == sizeof good);
    CHECK(opens(good, n));

    // Every byte is under the MAC, or is the MAC. Flipping one bit of any of
    // them closes the cookie, which is what holds the whole body rather than
    // the part a reader happens to compare.
    for (size_t i = 0; i < n; i++) {
        uint8_t bad[COOKIE_SHA256_LEN];
        memcpy(bad, good, n);
        bad[i] ^= 0x01;
        CHECK(!opens(bad, n));
    }

    // A cookie whose version byte is not SRV_COOKIE_VERSION does not open.
    // The mint writes only this format's version, so the case moves the byte
    // after minting and the MAC no longer matches either; what it holds is
    // that the version is not ignored.
    uint8_t versioned[COOKIE_SHA256_LEN];
    memcpy(versioned, good, n);
    versioned[0] = SRV_COOKIE_VERSION + 1;
    CHECK(!opens(versioned, n));

    // A cookie naming AES-128-GCM does not open here, because this build
    // holds no such suite and therefore no hash length for it.
    uint8_t suited[COOKIE_SHA256_LEN];
    memcpy(suited, good, n);
    suited[1] = 0x13;
    suited[2] = 0x01;
    CHECK(!opens(suited, n));
}

static void test_cookie_bounds(void) {
    uint8_t good[COOKIE_SHA256_LEN];
    size_t n = mint(good, sizeof good, mint_key);

    // The length the suite fixes, at both ends: one byte short and one byte
    // long are both refused, and the exact length opens.
    CHECK(opens(good, n));
    CHECK(!opens(good, n - 1));
    uint8_t longer[COOKIE_SHA256_LEN + 1];
    memcpy(longer, good, n);
    longer[n] = 0x00;
    CHECK(!opens(longer, n + 1));

    // A cookie too short to hold even the 5-byte head is refused by the
    // reader rather than by a read past its end.
    CHECK(!opens(good, 0));
    CHECK(!opens(good, 4));

    // The mint's capacity pair: the cookie's own length works and one byte
    // below it writes nothing.
    uint8_t probe[COOKIE_SHA256_LEN];
    memset(probe, 0xa5, sizeof probe);
    CHECK(mint(probe, n - 1, mint_key) == 0);
    for (size_t i = 0; i < sizeof probe; i++) {
        CHECK(probe[i] == 0xa5);
    }
    CHECK(mint(probe, n, mint_key) == n);

    // The mint's hash_len pair, at both ends of the range srv_cookie.h gives
    // it. SRV_COOKIE_HASH_MAX mints the longest cookie the format allows, and
    // one byte past it refuses.
    uint8_t wide[SRV_COOKIE_MAX];
    uint8_t wide_hash[SRV_COOKIE_HASH_MAX];
    memset(wide_hash, 0x77, sizeof wide_hash);
    CHECK(srv_cookie_mint(mint_key, SUITE_CHACHA20_POLY1305_SHA256, CH_KEX_GROUP, wide_hash,
                          SHA256_LEN - 1, frozen_in, wide, sizeof wide) == 0);
    CHECK(srv_cookie_mint(mint_key, SUITE_CHACHA20_POLY1305_SHA256, CH_KEX_GROUP, wide_hash,
                          SRV_COOKIE_HASH_MAX, frozen_in, wide, sizeof wide) == SRV_COOKIE_MAX);
    CHECK(srv_cookie_mint(mint_key, SUITE_CHACHA20_POLY1305_SHA256, CH_KEX_GROUP, wide_hash,
                          SRV_COOKIE_HASH_MAX + 1, frozen_in, wide, sizeof wide) == 0);

    // That longest cookie names a suite whose hash is 32 bytes, so this build
    // refuses to open it: the length the suite fixes and the length the
    // cookie has disagree.
    CHECK(!opens(wide, SRV_COOKIE_MAX));
}

#endif
