// The server's cipher suite selection, for a build that has two. Its own
// header because test/srv_flight_tests.h is at the 500-line cap CLAUDE.md
// sets, and because these cases compile only under -DCH_SUITE_AES_GCM
// while every case in that file compiles in both builds.
//
// bin/srv_flight_test_aes is the binary that runs them. It reads the same
// fixtures test/srv_flight_tests.h sets up, so the two files are one test
// split by build rather than two tests.
#ifndef CH_SRV_FLIGHT_SUITE_TESTS_H
#define CH_SRV_FLIGHT_SUITE_TESTS_H
#ifdef CH_SUITE_AES_GCM

#include "srv_flight_tests.h"

// Which suite srv_select picks, in a build that has two. The preference
// is ChaCha20 whenever the client offers it: both suites meet the
// profile, and ChaCha20 is constant time by construction where AES is
// constant time because the build said so (srv_flight.c states it).
//
// It runs only under -DCH_SUITE_AES_GCM. A build with one suite has
// nothing to choose between, and SRV_SUITE_AES_128_GCM is not declared
// there at all.
static void test_flight_select_suite(void) {
    selection sel;

    // Both offered: the one that needs no statement about the hardware.
    flight_reset();
    offer_x25519();
    flight_hello.suites = SRV_SUITE_CHACHA20_POLY1305 | SRV_SUITE_AES_128_GCM;
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_OK);
    CHECK(sel.suite == SUITE_CHACHA20_POLY1305_SHA256);
    CHECK(sel.hash_len == SHA256_LEN);

    // AES alone: selected, which is the whole point of carrying it. A
    // client that offers only this is the one RFC 9846 section 9.1 exists
    // for, and the build without the suite answers handshake_failure.
    offer_x25519();
    flight_hello.suites = SRV_SUITE_AES_128_GCM;
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_OK);
    CHECK(sel.suite == SUITE_AES_128_GCM_SHA256);
    CHECK(sel.hash_len == SHA256_LEN);

    // ChaCha20 alone: unchanged from a one-suite build.
    offer_x25519();
    flight_hello.suites = SRV_SUITE_CHACHA20_POLY1305;
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_OK);
    CHECK(sel.suite == SUITE_CHACHA20_POLY1305_SHA256);

    // Neither: still handshake_failure, and no suite written.
    offer_x25519();
    flight_hello.suites = 0;
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_EPROTO && hs.alert == ALERT_HANDSHAKE_FAILURE);
}

// The HelloRetryRequest round for a client that offers AES-GCM and no
// ChaCha20. The server selects AES-GCM, mints a cookie that names it, and
// must accept that cookie when the second hello echoes it. The first
// SUITE=aesgcm server refused it: srv_cookie_open knew ChaCha20 alone, so
// every such client that sent no key share failed its retried hello with
// illegal_parameter.
static void test_flight_retry_suite(void) {
    selection sel;
    flight_reset();
    srv_begin(&hs);
    offer_x25519();
    parse_result.suites = SRV_SUITE_AES_128_GCM;
    parse_result.shares = 0;
    feed_handshake(HS_CLIENT_HELLO, FLIGHT_HELLO_BODY);
    CHECK(srv_read_client_hello(&hs, &flight_hello) == CH_OK);
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_OK && sel.need_retry == 1);
    CHECK(sel.suite == SUITE_AES_128_GCM_SHA256);
    CHECK(srv_send_hello_retry_request(&hs, &flight_hello, &sel) == CH_OK);

    memcpy(cookie_echo, hs.cookie, hs.cookie_len);
    flight_hello.cookie = cookie_echo;
    flight_hello.cookie_len = hs.cookie_len;
    flight_hello.shares = flight_hello.groups;
    selection second;
    memset(&second, 0, sizeof second);
    CHECK(srv_check_retry_hello(&hs, &flight_hello, &second) == CH_OK);
    CHECK(second.suite == SUITE_AES_128_GCM_SHA256 && second.hash_len == SHA256_LEN);
    CHECK(second.group == sel.group && second.need_retry == 0);
}

// The cookie length an AES-GCM suite fixes, at its exact boundary. The
// suite hashes with SHA-256, so the cookie is 5 + 3 * SHA256_LEN bytes:
// that length opens and reports the suite, and one byte less or one byte
// more is refused before the MAC runs.
static void test_flight_cookie_suite_length(void) {
    static const uint8_t ch1_hash[SHA256_LEN] = {0x80, 0x81, 0x82, 0x83};
    static const uint8_t frozen[SHA256_LEN] = {0xc0, 0xc1, 0xc2, 0xc3};
    uint8_t cookie[SRV_COOKIE_MAX + 1];
    uint16_t suite = 0;
    uint16_t group = 0;
    size_t hash_len = 0;
    uint8_t hash_out[SRV_COOKIE_HASH_MAX];
    uint8_t frozen_out[SHA256_LEN];

    memset(cookie, 0, sizeof cookie);
    size_t n = srv_cookie_mint(cookie_key, SUITE_AES_128_GCM_SHA256, CH_GROUP_X25519, ch1_hash,
                               SHA256_LEN, frozen, cookie, sizeof cookie);
    CHECK(n == 5 + 3 * SHA256_LEN);
    CHECK(srv_cookie_open(cookie_key, cookie, n, &suite, &group, hash_out, &hash_len, frozen_out) ==
          CH_OK);
    CHECK(suite == SUITE_AES_128_GCM_SHA256 && hash_len == SHA256_LEN);
    CHECK(srv_cookie_open(cookie_key, cookie, n - 1, &suite, &group, hash_out, &hash_len,
                          frozen_out) == CH_EPROTO);
    CHECK(srv_cookie_open(cookie_key, cookie, n + 1, &suite, &group, hash_out, &hash_len,
                          frozen_out) == CH_EPROTO);
}

// Whether one record w seals opens under r.
static int seals_and_opens(rec_dir *w, rec_dir *r) {
    static const uint8_t note[3] = {1, 2, 3};
    uint8_t sealed[64];
    uint8_t plain[64];
    size_t sealed_len = 0;
    size_t plain_len = 0;
    uint8_t inner = 0;
    return rec_seal(w, REC_HANDSHAKE, note, sizeof note, sealed, sizeof sealed, &sealed_len) == 0 &&
           rec_open(r, sealed, sealed_len, plain, sizeof plain, &plain_len, &inner) == 0 &&
           plain_len == sizeof note && memcmp(plain, note, sizeof note) == 0;
}

// The suite srv_select picked is the one every direction the server keys
// runs: both handshake keys, the write direction's application key after
// the server Finished, and the read direction's after the client's. Each
// check pairs the server's direction with one keyed on its own from the
// same secret as AES-GCM, the way a client that took the ServerHello's
// suite keys it, so a server that keyed ChaCha20 fails every one.
static void test_flight_key_suite(void) {
    selection sel;
    rec_dir peer;
    hello_exchange_offering(&sel, SRV_SUITE_AES_128_GCM);
    CHECK(sel.suite == SUITE_AES_128_GCM_SHA256);
    CHECK(srv_derive_handshake_secrets(&hs, &flight_hello, &sel) == CH_OK);
    rec_dir_init_suite(&peer, hs.s_hs, SUITE_AES_128_GCM_SHA256);
    CHECK(seals_and_opens(&sess.wr, &peer));
    rec_dir_init_suite(&peer, hs.c_hs, SUITE_AES_128_GCM_SHA256);
    CHECK(seals_and_opens(&peer, &sess.rd));

    CHECK(srv_send_finished(&hs) == CH_OK);
    rec_dir_init_suite(&peer, sess.wr_secret, SUITE_AES_128_GCM_SHA256);
    CHECK(seals_and_opens(&sess.wr, &peer));
    srv_complete(&hs);
    rec_dir_init_suite(&peer, sess.rd_secret, SUITE_AES_128_GCM_SHA256);
    CHECK(seals_and_opens(&peer, &sess.rd));
}

#endif // CH_SUITE_AES_GCM
#endif
