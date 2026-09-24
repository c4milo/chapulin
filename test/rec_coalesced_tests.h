// The client Finished and the first application record in one delivery,
// the segment h2spec sends: its HTTP/2 preface rides in the same TCP
// segment as its Finished. ch_srv_record_in takes records up to and
// including the one that completes the handshake and stops there, so
// *consumed covers the Finished alone and the application record is left
// for ch_read. Before it stopped, the next record reached the completed
// handshake and failed it with unexpected_message, which colibri found
// against h2spec. Included by test/rec_loop_test.c; it reuses
// rec_read_tests.h's held records and held_recv.
#ifndef CH_TEST_REC_COALESCED_TESTS_H
#define CH_TEST_REC_COALESCED_TESTS_H

#include "rec_read_tests.h"

static void test_finished_and_data_in_one_delivery(ch_record *client, ch_record *server,
                                                   const ch_cfg *ccfg, const ch_cfg *scfg) {
    to_client.len = 0;
    CHECK(ch_srv_record_init(server, scfg) == CH_OK);
    CHECK(ch_record_init(client, ccfg) == CH_OK);
    // One round trip: the ClientHello in, the server's flight back.
    CHECK(client_to_server(client, server));
    CHECK(server_to_client(client));

    // The client's Finished, then one application record sealed under the
    // write key the client installed with it.
    uint8_t wire[WIRE_MAX];
    size_t total = 0;
    for (;;) {
        size_t n = 0;
        CHECK(ch_record_out(client, wire + total, sizeof wire - total, &n) == CH_OK);
        if (n == 0) {
            break;
        }
        total += n;
    }
    size_t finished_len = total;
    CHECK(finished_len > 0);
    CHECK(ch_record_state(client) == CH_ST_CONNECTED);
    static const uint8_t ping[4] = {'p', 'i', 'n', 'g'};
    size_t out_len = 0;
    CHECK(rec_seal(&client->t.wr, REC_APPDATA, ping, sizeof ping, wire + total, sizeof wire - total,
                   &out_len) == 0);
    total += out_len;

    size_t consumed = 0;
    int rc = ch_srv_record_in(server, wire, total, &consumed);
    CHECK(rc == CH_OK);
    CHECK(consumed == finished_len);
    CHECK(ch_record_state(server) == CH_ST_CONNECTED);

    // The bytes past *consumed belong to ch_read, which takes them
    // through recv once the session is connected.
    held.len = total - consumed;
    held.off = 0;
    memcpy(held.bytes, wire + consumed, held.len);
    server->t.cfg.recv = held_recv;
    uint8_t got[16];
    CHECK(ch_read(&server->t, got, sizeof got) == (int)sizeof ping);
    CHECK(memcmp(got, ping, sizeof ping) == 0);
}

#endif
