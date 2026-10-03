// The host object's multiply rows of the QUIC loop (docs/decisions.md 87
// and 89): test/quic_loop_test.c built as bin/quic_loop_host, the
// ROLE=both TRUST=webpki host object, with the files built on the
// widening multiply compiled under test/widemul_runtime_count.h's counts,
// which the binary says with -DTEST_WIDEMUL_COUNTED. Each end's
// ch_cfg.cpu comes from client_cpu and server_cpu in
// test/quic_loop_test.c. Every other row of that file runs in the same
// binary with both ends describing the CPU as TEST_CPU, which holds
// CH_CPU_CONSTANT_TIME_MULTIPLY.
//
// What the rows hold: in a whole handshake, and a Handshake packet and a
// 1-RTT packet each way, each end runs every operation on the copy its
// own ch_cfg.cpu names, the native copies with
// CH_CPU_CONSTANT_TIME_MULTIPLY and the files under their own names
// without it, and no operation on the other copy, for each of the four
// pairs of values: the hybrid key exchange, the server's P-256 signature
// and the packets' Poly1305.
#ifndef CH_TEST_QUIC_LOOP_WIDEMUL_H
#define CH_TEST_QUIC_LOOP_WIDEMUL_H
#ifdef TEST_WIDEMUL_COUNTED

#include "widemul_runtime_count.h"

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
static void check_quic_multiply_bit(int client_stated, int server_stated) {
    static uint8_t buf[4096];
    size_t n = 0;
    ch_cfg scfg;
    ch_cfg ccfg;
    client_cpu = widemul_row_cpu(TEST_CPU, client_stated);
    server_cpu = widemul_row_cpu(TEST_CPU, server_stated);
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
    CHECK(widemul_ran_own_copy(&client_calls, client_cpu));
    CHECK(widemul_ran_own_copy(&server_calls, server_cpu));
    client_cpu = TEST_CPU;
    server_cpu = TEST_CPU;
}

static void test_quic_multiply_bit(void) {
    for (int client_stated = 0; client_stated < 2; client_stated++) {
        for (int server_stated = 0; server_stated < 2; server_stated++) {
            check_quic_multiply_bit(client_stated, server_stated);
        }
    }
}

#endif // TEST_WIDEMUL_COUNTED
#endif
