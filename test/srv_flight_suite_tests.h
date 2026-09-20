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
    offer_everything();
    flight_hello.suites = SRV_SUITE_CHACHA20_POLY1305 | SRV_SUITE_AES_128_GCM;
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_OK);
    CHECK(sel.suite == SUITE_CHACHA20_POLY1305_SHA256);
    CHECK(sel.hash_len == SHA256_LEN);

    // AES alone: selected, which is the whole point of carrying it. A
    // client that offers only this is the one RFC 9846 section 9.1 exists
    // for, and the build without the suite answers handshake_failure.
    offer_everything();
    flight_hello.suites = SRV_SUITE_AES_128_GCM;
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_OK);
    CHECK(sel.suite == SUITE_AES_128_GCM_SHA256);
    CHECK(sel.hash_len == SHA256_LEN);

    // ChaCha20 alone: unchanged from a one-suite build.
    offer_everything();
    flight_hello.suites = SRV_SUITE_CHACHA20_POLY1305;
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_OK);
    CHECK(sel.suite == SUITE_CHACHA20_POLY1305_SHA256);

    // Neither: still handshake_failure, and no suite written.
    offer_everything();
    flight_hello.suites = 0;
    CHECK(srv_select(&hs, &flight_hello, &sel) == CH_EPROTO && hs.alert == ALERT_HANDSHAKE_FAILURE);
}

#endif // CH_SUITE_AES_GCM
#endif
