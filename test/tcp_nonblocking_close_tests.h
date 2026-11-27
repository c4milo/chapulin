// Closing a TRANSPORT=tcp-nonblocking session, one direction at a time, between
// this tree's two tcp-nonblocking drivers. A close_notify closes its sender's
// direction alone (RFC 9846 §6, rfc9846.txt:3767-3768, and §6.1,
// rfc9846.txt:3857-3859), so the side that receives one still writes, and
// writes its own close_notify when its caller calls ch_close_out, which
// puts the record in the caller's storage and sends nothing itself
// (tcp_nonblocking.h). Included by test/tcp_nonblocking_loop_test.c; it
// reuses tcp_nonblocking_read_tests.h's held records, held_recv and
// hold_record for what the server sends the client.
//
// colibri found the old behavior: ch_read answered the peer's
// close_notify by calling ch_close, which sent this side's close_notify
// through cfg.send from inside ch_read and wiped the write key. colibri's
// adapter holds only input during ch_read, so that alert was lost, and
// its own ch_close later sent nothing because the keys were gone. So
// this test counts every send call each end makes, the caller's own
// sends of the records ch_close_out wrote among them.
#ifndef CH_TEST_TCP_NONBLOCKING_CLOSE_TESTS_H
#define CH_TEST_TCP_NONBLOCKING_CLOSE_TESTS_H

#include "session_convert.h"
#include "tcp_nonblocking_read_tests.h"
#include "test_write.h"

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
    return (int)n;
}

// Hands over what the client sent, and 0 when it has sent nothing more,
// which is tcp_nonblocking.h's recv contract.
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
    return (int)n;
}

// The close_notify that out holds, out_len bytes: one record of
// CH_ALERT_RECORD_LEN bytes that opens under a copy of reader to the
// warning alert close_notify (RFC 9846 §6.1). The copy leaves the reader's
// key where it was.
static void check_close_notify(const uint8_t *out, size_t out_len, const rec_dir *reader) {
    CHECK(out_len == CH_ALERT_RECORD_LEN);
    rec_dir copy = *reader;
    uint8_t pt[CH_ALERT_RECORD_LEN];
    size_t pt_len = 0;
    uint8_t type = 0;
    CHECK(rec_open(&copy, out, out_len, pt, sizeof pt, &pt_len, &type) == 0);
    CHECK(type == REC_ALERT && pt_len == 2 && pt[0] == 1 && pt[1] == ALERT_CLOSE_NOTIFY);
}

// ch_close_out's refusals on r, none of which writes a byte of out or
// *out_len or changes the session: CH_EINVAL for a cap below
// CH_ALERT_RECORD_LEN and for a NULL out, and CH_EPROTO on a session that
// is not connected, for a call with room for the record.
static void check_close_out_refused(ch_tcp_priv *r) {
    uint8_t out[CH_ALERT_RECORD_LEN];
    memset(out, 0xEE, sizeof out);
    size_t out_len = 0;
    uint8_t state = ch_tcp_state(tcp_public(r));
    CHECK(ch_close_out(tls_public(&r->t), out, sizeof out - 1, &out_len) == CH_EINVAL);
    CHECK(ch_close_out(tls_public(&r->t), NULL, sizeof out, &out_len) == CH_EINVAL);
    if (state != CH_ST_CONNECTED) {
        CHECK(ch_close_out(tls_public(&r->t), out, sizeof out, &out_len) == CH_EPROTO);
    }
    CHECK(out_len == 0 && ch_tcp_state(tcp_public(r)) == state);
    uint8_t any = 0;
    for (size_t i = 0; i < sizeof out; i++) {
        any |= (uint8_t)(out[i] ^ 0xEE);
    }
    CHECK(any == 0);
}

// One ch_close_out on the connected r: this side's close_notify into out,
// sealed under r's write key, and no send through cfg.send. The session
// is CH_ST_CLOSED after it. The caller then sends the record through
// send, as a caller hands its socket the bytes.
static void close_and_send(ch_tcp_priv *r, const size_t *sends,
                           int (*send)(void *io, const uint8_t *p, size_t n)) {
    check_close_out_refused(r);
    // A copy of the write key opens what the call seals under it.
    rec_dir reader = r->t.wr;
    size_t sends_before = *sends;
    uint8_t out[CH_ALERT_RECORD_LEN];
    size_t out_len = 0;
    CHECK(ch_close_out(tls_public(&r->t), out, sizeof out, &out_len) == CH_OK);
    CHECK(*sends == sends_before && ch_tcp_state(tcp_public(r)) == CH_ST_CLOSED);
    check_close_notify(out, out_len, &reader);
    CHECK(send(NULL, out, out_len) == (int)out_len);
    check_close_out_refused(r);
}

// The server closes its direction first and the client its own after;
// then the server, which read the client's close_notify, still writes
// and closes. chapulin has no call that writes a close_notify and keeps
// the session, so the server's first close_notify is sealed here under
// its write key, as a peer that closes one direction sends it.
static void test_close_one_direction(ch_tcp_priv *client, ch_tcp_priv *server, const ch_cfg *ccfg,
                                     const ch_cfg *scfg) {
    io_calls = 0;
    (void)run_handshake(client, server, ccfg, scfg);
    CHECK(ch_tcp_state(tcp_public(client)) == CH_ST_CONNECTED);
    CHECK(ch_tcp_state(tcp_public(server)) == CH_ST_CONNECTED);
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

    // The read of the close_notify writes nothing into reply: RFC 9846
    // §6.1 dropped the answer TLS 1.2 owed, and the client's own
    // close_notify waits for its caller's ch_close_out (INV-22).
    uint8_t reply[CH_ALERT_RECORD_LEN];
    memset(reply, 0xEE, sizeof reply);
    ch_read_result result;
    CHECK(ch_read_in_place(tls_public(&client->t), held.bytes + held.off, close_end - held.off,
                           reply, sizeof reply, &result) == CH_ECLOSED);
    CHECK(result.reply_len == 0 && reply[0] == 0xEE && result.consumed == close_end - held.off);
    held.off += result.consumed;

    // The client reads 0 and sends nothing, however often it asks, and
    // the record after the close_notify stays unread.
    uint8_t got[32];
    CHECK(test_read(tls_public(&client->t), got, sizeof got) == 0);
    CHECK(client_sends == 0);
    CHECK(held.off == close_end);
    CHECK(ch_tcp_state(tcp_public(client)) == CH_ST_CONNECTED && client->t.read_closed == 1);
    CHECK(test_read(tls_public(&client->t), got, sizeof got) == 0);
    CHECK(client_sends == 0 && held.off == close_end);
    // The exporter secret is not a read key, so it lives until ch_close_out.
    uint8_t exported[SHA256_LEN];
    CHECK(ch_export(tls_public(&client->t), "EXPORTER-Channel-Binding", NULL, 0, exported,
                    sizeof exported) == CH_OK);

    // The client still writes, and the server reads it.
    static const uint8_t bye[3] = {'b', 'y', 'e'};
    CHECK(test_write(tls_public(&client->t), bye, sizeof bye) == CH_OK);
    CHECK(client_sends == 1);
    CHECK(test_read(tls_public(&server->t), got, sizeof got) == (int)sizeof bye);
    CHECK(memcmp(got, bye, sizeof bye) == 0);

    // The client's ch_close_out writes its close_notify, one record of the
    // length tls.h names, which its caller sends. The server reads 0 and
    // sends nothing in answer.
    size_t before_close = to_server.len;
    close_and_send(client, &client_sends, client_send);
    CHECK(client_sends == 2);
    CHECK(to_server.len - before_close == CH_ALERT_RECORD_LEN);
    CHECK(ch_tcp_state(tcp_public(client)) == CH_ST_CLOSED);
    CHECK(ch_export(tls_public(&client->t), "EXPORTER-Channel-Binding", NULL, 0, exported,
                    sizeof exported) == CH_EINVAL);
    CHECK(test_read(tls_public(&server->t), got, sizeof got) == 0);
    CHECK(server_sends == 0);
    CHECK(to_server.off == to_server.len);
    CHECK(ch_tcp_state(tcp_public(server)) == CH_ST_CONNECTED && server->t.read_closed == 1);

    // The server's own direction is still open until its ch_close_out.
    static const uint8_t tail[4] = {'c', 'h', 'a', 'u'};
    CHECK(test_write(tls_public(&server->t), tail, sizeof tail) == CH_OK);
    CHECK(server_sends == 1);
    before_close = held.len;
    close_and_send(server, &server_sends, server_send);
    CHECK(server_sends == 2);
    CHECK(held.len - before_close == CH_ALERT_RECORD_LEN);
    CHECK(ch_tcp_state(tcp_public(server)) == CH_ST_CLOSED);
    CHECK(test_write(tls_public(&server->t), tail, sizeof tail) == CH_EPROTO);
    ch_tcp_close(tcp_public(client));
    ch_tcp_close(tcp_public(server));
    CHECK(io_calls == 0);
}

#endif
