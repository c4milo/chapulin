// The three cipher suites over QUIC, end to end: this tree's QUIC
// TRUST=webpki client against this tree's QUIC server in the ROLE=both
// TRANSPORT=quic-nonblocking TRUST=webpki object compiled with -DCH_SUITE_AES_GCM.
// bin/quic_loop_aes runs them; test/quic_loop_test.c includes this file
// after quic_loop_webpki.h, and a build without the define compiles none
// of it.
//
// Each row names one suite in ch_srv_cfg.cipher_suites and runs a full
// handshake and then the ticket it issued resumed, both at that suite.
// Every Handshake and 1-RTT packet of the row runs the suite's AEAD and
// header protection (RFC 9001 §5.3, §5.4.3), the Initial packets
// AES-128-GCM under their public keys, and a 1-RTT key update keeps the
// suite (§6.1). TLS_AES_256_GCM_SHA384 runs its key schedule and the
// ticket's PSK on SHA-384 too.
#ifndef CH_TEST_QUIC_LOOP_SUITES_H
#define CH_TEST_QUIC_LOOP_SUITES_H
#ifdef CH_SUITE_AES_GCM

#include "quic_packet.h"

// The server's order for one row, in static storage because the config
// keeps the pointer for the life of the session.
static uint16_t row_suite;

static void webpki_server_suite(ch_cfg *cfg, uint16_t suite) {
    webpki_server(cfg, ticket_key);
    row_suite = suite;
    cfg->srv.cipher_suites = &row_suite;
    cfg->srv.cipher_suite_count = 1;
}

// The 1-RTT keys agree after a key update: the server updates, seals
// with the Key Phase bit it now names, and the client opens the packet
// with its next receive set, which ch_quic_key_update derived at the
// suite's hash for the suite's AEAD.
static void check_keys_agree_after_update(void) {
    CHECK(ch_quic_key_update(&server) == CH_OK);
    uint8_t hdr[3] = {0x41, 0x00, 0x06};
    hdr[0] |= (uint8_t)(ch_quic_key_phase(&server) ? QUIC_KEY_PHASE_BIT : 0);
    static const uint8_t pt[24] = {'u', 'p', 'd', 'a', 't', 'e'};
    uint8_t pkt[64];
    size_t pkt_len = 0;
    CHECK(ch_quic_seal(&server, CH_LEVEL_APPLICATION, 6, 2, hdr, sizeof hdr, pt, sizeof pt, pkt,
                       sizeof pkt, &pkt_len) == CH_OK);
    uint8_t key_set = 0;
    uint64_t pn = 0;
    size_t pt_len = 0;
    CHECK(ch_quic_open(&client, CH_LEVEL_APPLICATION, pkt, pkt_len, 1, 5, 0, &key_set, &pn,
                       &pt_len) == CH_OK);
    CHECK(key_set == CH_QUIC_KEY_NEXT && pn == 6 && pt_len == sizeof pt);
}

// One suite, full and resumed, with the 1-RTT keys checked each time and
// a key update after the full handshake.
static void check_quic_suite(uint16_t suite) {
    ch_cfg scfg;
    ch_cfg ccfg;
    webpki_server_suite(&scfg, suite);
    webpki_client(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(client.t.suite == suite && server.t.suite == suite);
    CHECK(client.t.psk_selected == 0 && server.t.psk_selected == 0);
    CHECK(handshake_messages() == 4);
    check_keys_agree();
    take_ticket();
    CHECK(kept.psk_len == suite_hash_len(suite));
    check_keys_agree_after_update();

    webpki_client(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    present_ticket(&ccfg);
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(client.t.suite == suite && server.t.suite == suite);
    CHECK(client.t.psk_selected == 1 && server.t.psk_selected == 1);
    CHECK(handshake_messages() == 2);
    check_keys_agree();
    take_ticket();
    CHECK(kept.psk_len == suite_hash_len(suite));
}

static void test_quic_suites(void) {
    check_quic_suite(SUITE_CHACHA20_POLY1305_SHA256);
    check_quic_suite(SUITE_AES_128_GCM_SHA256);
    check_quic_suite(SUITE_AES_256_GCM_SHA384);
}

#endif // CH_SUITE_AES_GCM
#endif
