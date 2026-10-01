// The WIDEMUL=runtime rows of the QUIC loop (docs/decisions.md 87):
// test/quic_loop_test.c built as bin/quic_loop_widemul, the ROLE=both
// TRUST=webpki WIDEMUL=runtime object, with the files built on the
// widening multiply compiled under test/widemul_runtime_count.h's counts.
// Each end's ch_cfg.widemul comes from quic_client_widemul and
// quic_server_widemul in test/quic_loop_test.c. Every other row of that
// file runs in the same binary with both ends answering TEST_WIDEMUL,
// CH_WIDEMUL_CONSTANT_TIME.
//
// What the rows hold: ch_quic_init and ch_srv_quic_init refuse
// ch_cfg.widemul at 0, the value a caller that never set it leaves, and at
// 3, the first value past the two answers, with CH_EINVAL and a failed
// session, and take each answer. In a whole handshake, and a Handshake
// packet and a 1-RTT packet each way, each end runs every operation on the
// copy its own answer names, and no operation on the other copy, for each
// of the four pairs of answers: the hybrid key exchange, the server's
// P-256 signature and the packets' Poly1305.
#ifndef CH_TEST_QUIC_LOOP_WIDEMUL_H
#define CH_TEST_QUIC_LOOP_WIDEMUL_H
#ifdef CH_WIDEMUL_RUNTIME

#include "widemul_runtime_count.h"

// Both init calls at each edge of the field: 0, each answer, and 3.
static void check_quic_widemul_edges(void) {
    static const uint8_t values[4] = {0, CH_WIDEMUL_CONSTANT_TIME, CH_WIDEMUL_NOT_STATED, 3};
    static const int taken[4] = {0, 1, 1, 0};
    static ch_quic probe;
    for (size_t i = 0; i < sizeof values; i++) {
        ch_cfg cfg;
        webpki_client(&cfg, webpki_corpus_anchors_root_p384, "s3.example.test");
        cfg.widemul = values[i];
        int rc = ch_quic_init(&probe, &cfg);
        CHECK(taken[i] ? rc == CH_OK : rc == CH_EINVAL && ch_quic_state(&probe) == CH_ST_FAILED);
        ch_quic_close(&probe);
        webpki_server(&cfg, ticket_key);
        cfg.widemul = values[i];
        rc = ch_srv_quic_init(&probe, &cfg);
        CHECK(taken[i] ? rc == CH_OK : rc == CH_EINVAL && ch_quic_state(&probe) == CH_ST_FAILED);
        ch_quic_close(&probe);
    }
}

// One packet at level sealed by from and opened by to, with each end's
// calls counted around its own call: a short header at the 1-RTT level and
// a long one at the Handshake level, each with empty connection IDs and a
// two-byte packet number.
static void quic_widemul_packet(uint8_t level, ch_quic *from, widemul_end_calls *from_calls,
                                ch_quic *to, widemul_end_calls *to_calls) {
    static const uint8_t short_hdr[3] = {0x41, 0x00, 0x05};
    static const uint8_t long_hdr[11] = {0xe1, 0x00, 0x00, 0x00, 0x01, 0x00,
                                         0x00, 0x40, 0x1a, 0x00, 0x05};
    static const uint8_t pt[24] = {'w', 'i', 'd', 'e', 'm', 'u', 'l'};
    const uint8_t *hdr = level == CH_LEVEL_APPLICATION ? short_hdr : long_hdr;
    size_t hdr_len = level == CH_LEVEL_APPLICATION ? sizeof short_hdr : sizeof long_hdr;
    uint8_t pkt[64];
    size_t pkt_len = 0;
    CHECK(ch_quic_seal(from, level, CH_QUIC_VERSION_1, 5, 2, hdr, hdr_len, pt, sizeof pt, pkt,
                       sizeof pkt, &pkt_len) == CH_OK);
    widemul_take_calls(from_calls);
    uint8_t key_set = 0;
    uint64_t pn = 0;
    size_t pt_len = 0;
    CHECK(ch_quic_open(to, level, CH_QUIC_VERSION_1, pkt, pkt_len, hdr_len - 2, 0, 0, &key_set, &pn,
                       &pt_len) == CH_OK);
    widemul_take_calls(to_calls);
    CHECK(pn == 5 && pt_len == sizeof pt && memcmp(pkt + hdr_len, pt, sizeof pt) == 0);
}

// run_quic_following in QUIC version 1, with each end's calls counted
// around that end's own calls, then a Handshake packet and a 1-RTT packet
// each way.
static void check_quic_widemul_answers(uint8_t client_answer, uint8_t server_answer) {
    static uint8_t buf[4096];
    size_t n = 0;
    ch_cfg scfg;
    ch_cfg ccfg;
    quic_client_widemul = client_answer;
    quic_server_widemul = server_answer;
    webpki_server(&scfg, ticket_key);
    webpki_client(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    memset(&from_server, 0, sizeof from_server);
    widemul_end_calls client_calls = {0, 0};
    widemul_end_calls server_calls = {0, 0};
    widemul_native_calls = 0;
    widemul_decomposed_calls = 0;
    CHECK(ch_quic_init(&client, &ccfg) == CH_OK);
    CHECK(ch_quic_crypto_out(&client, CH_LEVEL_INITIAL, buf, sizeof buf, &n) == CH_OK);
    widemul_take_calls(&client_calls);
    CHECK(ch_srv_quic_init(&server, &scfg) == CH_OK);
    CHECK(ch_srv_quic_crypto_in(&server, CH_LEVEL_INITIAL, buf, n) == CH_OK);
    widemul_take_calls(&server_calls);
    CHECK(ch_quic_crypto_in(&client, CH_LEVEL_INITIAL, from_server.bytes[CH_LEVEL_INITIAL],
                            from_server.len[CH_LEVEL_INITIAL]) == CH_OK);
    CHECK(ch_quic_crypto_in(&client, CH_LEVEL_HANDSHAKE, from_server.bytes[CH_LEVEL_HANDSHAKE],
                            from_server.len[CH_LEVEL_HANDSHAKE]) == CH_OK);
    CHECK(ch_quic_crypto_out(&client, CH_LEVEL_HANDSHAKE, buf, sizeof buf, &n) == CH_OK);
    widemul_take_calls(&client_calls);
    CHECK(ch_srv_quic_crypto_in(&server, CH_LEVEL_HANDSHAKE, buf, n) == CH_OK);
    widemul_take_calls(&server_calls);
    CHECK(ch_quic_state(&client) == CH_ST_CONNECTED && ch_quic_state(&server) == CH_ST_CONNECTED);
    static const uint8_t levels[2] = {CH_LEVEL_HANDSHAKE, CH_LEVEL_APPLICATION};
    for (size_t i = 0; i < sizeof levels; i++) {
        quic_widemul_packet(levels[i], &server, &server_calls, &client, &client_calls);
        quic_widemul_packet(levels[i], &client, &client_calls, &server, &server_calls);
    }
    CHECK(widemul_ran_own_copy(&client_calls, client_answer));
    CHECK(widemul_ran_own_copy(&server_calls, server_answer));
    quic_client_widemul = TEST_WIDEMUL;
    quic_server_widemul = TEST_WIDEMUL;
}

static void test_quic_widemul(void) {
    check_quic_widemul_edges();
    static const uint8_t answers[2] = {CH_WIDEMUL_CONSTANT_TIME, CH_WIDEMUL_NOT_STATED};
    for (size_t c = 0; c < sizeof answers; c++) {
        for (size_t s = 0; s < sizeof answers; s++) {
            check_quic_widemul_answers(answers[c], answers[s]);
        }
    }
}

#endif // CH_WIDEMUL_RUNTIME
#endif
