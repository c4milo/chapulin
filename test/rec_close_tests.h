// Closing a TRANSPORT=tcp-nonblocking session, one direction at a time, between
// this tree's two tcp-nonblocking drivers. A close_notify closes its
// sender's direction alone (RFC 9846 §6, rfc9846.txt:3767-3768, and
// §6.1, rfc9846.txt:3857-3859), so the side that receives one still
// writes, and sends its own close_notify when its caller calls ch_close.
// Included by test/rec_loop_test.c; it reuses rec_read_tests.h's held
// records, held_recv and hold_record for what the server sends the
// client.
//
// colibri found the old behavior: ch_read answered the peer's
// close_notify by calling ch_close, which sent this side's close_notify
// through cfg.send from inside ch_read and wiped the write key. colibri's
// adapter holds only input during ch_read, so that alert was lost, and
// its own ch_close later sent nothing because the keys were gone. So
// this test counts every send call each end makes.
#ifndef CH_TEST_REC_CLOSE_TESTS_H
#define CH_TEST_REC_CLOSE_TESTS_H

#include "rec_read_tests.h"

// What the client sent through cfg.send, for the server's recv.
static struct {
    uint8_t bytes[WIRE_MAX];
    size_t len;
    size_t off;
} to_server;

// Send calls each end made once connected.
static size_t client_sends;
static size_t server_sends;

static int client_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    client_sends++;
    if (to_server.len + n > sizeof to_server.bytes) {
        return -1;
    }
    memcpy(to_server.bytes + to_server.len, p, n);
    to_server.len += n;
    return 0;
}

// Hands over what the client sent, and 0 when it has sent nothing more,
// which is rec.h's recv contract.
static int server_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    size_t left = to_server.len - to_server.off;
    size_t take = n < left ? n : left;
    memcpy(p, to_server.bytes + to_server.off, take);
    to_server.off += take;
    return (int)take;
}

// The server's records go where hold_record puts them, in held, which
// the client reads through held_recv.
static int server_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    server_sends++;
    if (held.len + n > sizeof held.bytes) {
        return -1;
    }
    memcpy(held.bytes + held.len, p, n);
    held.len += n;
    return 0;
}

// The server closes its direction first and the client its own after;
// then the server, which read the client's close_notify, still writes
// and closes. chapulin has no call that sends a close_notify and keeps
// the session, so the server's first close_notify is sealed here under
// its write key, as a peer that closes one direction sends it.
static void test_close_one_direction(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                                     const ch_cfg *scfg) {
    io_calls = 0;
    (void)run_handshake(client, server, ccfg, scfg);
    CHECK(ch_record_state(client) == CH_ST_CONNECTED);
    CHECK(ch_record_state(server) == CH_ST_CONNECTED);
    memset(&held, 0, sizeof held);
    memset(&to_server, 0, sizeof to_server);
    client_sends = 0;
    server_sends = 0;
    client->t.cfg.send = client_send;
    client->t.cfg.recv = held_recv;
    server->t.cfg.send = server_send;
    server->t.cfg.recv = server_recv;

    static const uint8_t close_notify[2] = {1, ALERT_CLOSE_NOTIFY};
    hold_record(server, REC_ALERT, close_notify, sizeof close_notify, 0);
    size_t close_end = held.len;
    static const uint8_t late[4] = {'t', 'a', 'r', 'd'};
    hold_record(server, REC_APPDATA, late, sizeof late, 0);

    // The client reads 0 and sends nothing, however often it asks, and
    // the record after the close_notify stays unread.
    uint8_t got[32];
    CHECK(ch_read(&client->t, got, sizeof got) == 0);
    CHECK(client_sends == 0);
    CHECK(held.off == close_end);
    CHECK(ch_record_state(client) == CH_ST_CONNECTED && client->t.read_closed == 1);
    CHECK(ch_read(&client->t, got, sizeof got) == 0);
    CHECK(client_sends == 0 && held.off == close_end);
    // The exporter secret is not a read key, so it lives until ch_close.
    uint8_t exported[SHA256_LEN];
    CHECK(ch_export(&client->t, "EXPORTER-Channel-Binding", NULL, 0, exported, sizeof exported) ==
          CH_OK);

    // The client still writes, and the server reads it.
    static const uint8_t bye[3] = {'b', 'y', 'e'};
    CHECK(ch_write(&client->t, bye, sizeof bye) == CH_OK);
    CHECK(client_sends == 1);
    CHECK(ch_read(&server->t, got, sizeof got) == (int)sizeof bye);
    CHECK(memcmp(got, bye, sizeof bye) == 0);

    // The client's ch_close sends its close_notify in one call. The
    // server reads 0 and sends nothing in answer.
    ch_close(&client->t);
    CHECK(client_sends == 2);
    CHECK(ch_record_state(client) == CH_ST_CLOSED);
    CHECK(ch_export(&client->t, "EXPORTER-Channel-Binding", NULL, 0, exported, sizeof exported) ==
          CH_EINVAL);
    CHECK(ch_read(&server->t, got, sizeof got) == 0);
    CHECK(server_sends == 0);
    CHECK(to_server.off == to_server.len);
    CHECK(ch_record_state(server) == CH_ST_CONNECTED && server->t.read_closed == 1);

    // The server's own direction is still open until its ch_close.
    static const uint8_t tail[4] = {'c', 'h', 'a', 'u'};
    CHECK(ch_write(&server->t, tail, sizeof tail) == CH_OK);
    CHECK(server_sends == 1);
    ch_close(&server->t);
    CHECK(server_sends == 2);
    CHECK(ch_record_state(server) == CH_ST_CLOSED);
    CHECK(ch_write(&server->t, tail, sizeof tail) == CH_EPROTO);
    ch_record_close(client);
    ch_record_close(server);
    CHECK(io_calls == 0);
}

#endif
