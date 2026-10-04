// The peer's alert between this tree's two tcp-nonblocking drivers, in
// the handshake and after it (RFC 9846 §5.1, §6 and §6.2), and what
// alert.h's two calls report after each.
//
// A fatal alert ends the session with CH_EPROTO and gets no answer. In
// the handshake that means a client stages nothing for ch_record_out and
// a server pushes nothing more; after it, ch_read calls no cfg.send.
// ch_alert_received names the alert either way, whether it came in the
// clear or protected, and a server reads one in the clear even after its
// flight, because a client that could not use the ServerHello has no key
// to protect it with. A record of the alert type that is not one 2-byte
// alert is answered with decode_error: in the handshake the client stages
// it and the server pushes it, in the clear before its write key and
// sealed after, and after the handshake ch_read sends it itself. Included
// by test/tcp_nonblocking_loop_test.c.
#ifndef CH_TEST_TCP_NONBLOCKING_ALERT_TESTS_H
#define CH_TEST_TCP_NONBLOCKING_ALERT_TESTS_H

#include "tcp_nonblocking_record_end_tests.h"

// One alert record of n bytes of plaintext from alert, into out: in the
// clear, or sealed under secret at the sequence number the reader's first
// protected record has. Returns its length.
static size_t alert_record(uint8_t *out, size_t cap, const uint8_t *alert, size_t n,
                           const uint8_t *secret) {
    size_t len = REC_HDR + n;
    if (secret != NULL) {
        rec_dir d;
        rec_dir_init(&d, secret);
        TEST_CPU_DIR(d);
        CHECK(rec_seal(&d, REC_ALERT, alert, n, out, cap, &len) == 0);
        return len;
    }
    const uint8_t hdr[REC_HDR] = {REC_ALERT, 0x03, 0x03, 0, (uint8_t)n};
    CHECK(cap >= len);
    memcpy(out, hdr, REC_HDR);
    memcpy(out + REC_HDR, alert, n);
    return len;
}

// What a session that read the alert of n bytes in its handshake reports.
static void check_handshake_alert(const ch_record *r, int rc, const uint8_t *alert, size_t n) {
    CHECK(rc == CH_EPROTO && ch_record_state(r) == CH_ST_FAILED);
    if (n == 2) {
        CHECK(ch_alert_received(&r->t) == alert[1] && ch_alert_sent(&r->t) == 0);
        return;
    }
    CHECK(ch_alert_received(&r->t) == 0 && ch_alert_sent(&r->t) == ALERT_DECODE_ERROR);
}

// The client reads the alert in place of the server's flight, or after
// the ServerHello under the server's handshake key. It stages nothing
// after a fatal alert, and decode_error after a record that is not one
// alert: in the clear in place of the flight, and sealed under the
// handshake write key the ServerHello gave it, which the server reads with.
static void client_reads_handshake_alert(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                                         const ch_cfg *scfg, int keyed, const uint8_t *alert,
                                         size_t n) {
    start_pair(client, server, ccfg, scfg);
    CHECK(client_to_server(client, server));
    uint8_t wire[WIRE_MAX];
    size_t len = 0;
    if (keyed) {
        len = record_at(to_client.bytes, 0);
        memcpy(wire, to_client.bytes, len);
    }
    len += alert_record(wire + len, sizeof wire - len, alert, n, keyed ? server->hs.s_hs : NULL);
    size_t consumed = 0;
    check_handshake_alert(client, ch_record_in(client, wire, len, &consumed), alert, n);
    uint8_t staged[64];
    size_t staged_len = take_client_alert(client, staged, sizeof staged);
    if (n == 2) {
        CHECK(staged_len == 0);
        return;
    }
    check_alert_record(staged, staged_len, keyed ? &server->t.rd : NULL, ALERT_DECODE_ERROR);
}

// The server reads the alert in place of the ClientHello (answer 0), or
// in answer to its flight: in the clear (1) or under the client's
// handshake key (2). It pushes nothing after a fatal alert, and
// decode_error after a record that is not one alert: in the clear in
// place of the ClientHello, and sealed under the write key its flight
// left it after that flight.
static void server_reads_handshake_alert(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                                         const ch_cfg *scfg, int answer, const uint8_t *alert,
                                         size_t n) {
    start_pair(client, server, ccfg, scfg);
    if (answer != 0) {
        CHECK(client_to_server(client, server));
    }
    size_t pushed = records_pushed;
    size_t before = to_client.len;
    rec_dir writer = server->t.wr;
    uint8_t wire[64];
    size_t len = alert_record(wire, sizeof wire, alert, n, answer == 2 ? server->hs.c_hs : NULL);
    size_t consumed = 0;
    check_handshake_alert(server, ch_srv_record_in(server, wire, len, &consumed), alert, n);
    if (n == 2) {
        CHECK(records_pushed == pushed);
        return;
    }
    CHECK(records_pushed == pushed + 1);
    check_alert_record(to_client.bytes + before, to_client.len - before,
                       answer != 0 ? &writer : NULL, ALERT_DECODE_ERROR);
}

// A connected pair whose records go through tcp_nonblocking_close_tests.h's
// wires, with every send counted: the client's into to_server, the
// server's into held.
static void connect_pair_on_wires(ch_record *client, ch_record *server, const ch_cfg *ccfg,
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
}

// After the handshake: the peer's alert under its application write key,
// read by the other end's ch_read. A fatal one calls no cfg.send, and a
// 3-byte one sends decode_error through cfg.send, once. Neither leaves the
// client a record for ch_record_out, which answers CH_EINVAL at once.
static void read_alert_after_handshake(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                                       const ch_cfg *scfg, int server_reads, const uint8_t *alert,
                                       size_t n) {
    connect_pair_on_wires(client, server, ccfg, scfg);
    ch_record *reader = server_reads ? server : client;
    size_t len = 0;
    if (server_reads) {
        CHECK(rec_seal(&client->t.wr, REC_ALERT, alert, n, to_server.bytes, WIRE_MAX, &len) == 0);
        to_server.len = len;
    } else {
        hold_record(server, REC_ALERT, alert, n, 0);
    }
    uint8_t got[16];
    CHECK(ch_read(&reader->t, got, sizeof got) == CH_EPROTO);
    CHECK(ch_record_state(reader) == CH_ST_FAILED);
    uint8_t staged[64];
    CHECK(server_reads || take_client_alert(client, staged, sizeof staged) == 0);
    size_t sends = server_reads ? server_sends : client_sends;
    if (n == 2) {
        CHECK(ch_alert_received(&reader->t) == alert[1] && ch_alert_sent(&reader->t) == 0);
        CHECK(sends == 0);
    } else {
        CHECK(ch_alert_received(&reader->t) == 0);
        CHECK(ch_alert_sent(&reader->t) == ALERT_DECODE_ERROR && sends == 1);
    }
    ch_record_close(client);
    ch_record_close(server);
    CHECK(io_calls == 0);
}

// A client's NewSessionTicket, read by the server after the handshake. RFC
// 9846 §4.7.1 gives the message to the server alone (rfc9846.txt:3194-3196),
// so the server refuses it as a message out of order, with
// unexpected_message (rfc9846.txt:1054-1058), where a client takes the
// server's (tcp_nonblocking_read_tests.h). The server's on_ticket, set here
// on purpose, sees nothing.
static void server_reads_client_ticket(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                                       const ch_cfg *scfg) {
    connect_pair_on_wires(client, server, ccfg, scfg);
    uint8_t ticket[32];
    size_t ticket_len = build_ticket(ticket, sizeof ticket);
    size_t len = 0;
    CHECK(rec_seal(&client->t.wr, REC_HANDSHAKE, ticket, ticket_len, to_server.bytes, WIRE_MAX,
                   &len) == 0);
    to_server.len = len;
    tickets_seen = 0;
    server->t.cfg.on_ticket = count_ticket;
    uint8_t got[16];
    CHECK(ch_read(&server->t, got, sizeof got) == CH_EPROTO);
    CHECK(tickets_seen == 0 && ch_record_state(server) == CH_ST_FAILED);
    CHECK(ch_alert_sent(&server->t) == ALERT_UNEXPECTED_MESSAGE && server_sends == 1);
    CHECK(held.len == CH_ALERT_RECORD_LEN);
    ch_record_close(client);
    ch_record_close(server);
    CHECK(io_calls == 0);
}

static void test_alerts(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                        const ch_cfg *scfg) {
    static const uint8_t alert[3] = {2, ALERT_BAD_CERTIFICATE, 0};
    expect_refusal = 1;
    for (size_t n = 2; n <= 3; n++) {
        client_reads_handshake_alert(client, server, ccfg, scfg, 0, alert, n);
        client_reads_handshake_alert(client, server, ccfg, scfg, 1, alert, n);
        server_reads_handshake_alert(client, server, ccfg, scfg, 0, alert, n);
        server_reads_handshake_alert(client, server, ccfg, scfg, 1, alert, n);
        server_reads_handshake_alert(client, server, ccfg, scfg, 2, alert, n);
        read_alert_after_handshake(client, server, ccfg, scfg, 0, alert, n);
        read_alert_after_handshake(client, server, ccfg, scfg, 1, alert, n);
    }
    server_reads_client_ticket(client, server, ccfg, scfg);
    expect_refusal = 0;
}

#endif
