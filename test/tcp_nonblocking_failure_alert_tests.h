// The alert record each tcp-nonblocking driver emits when its handshake
// fails, between this tree's two drivers (tcp_nonblocking.h). The client
// stages it for ch_record_out and the server pushes it through
// cfg.srv.on_record_out. The caller holds no key, so the driver seals the
// record under its write key once it has one, as RFC 9846 §6 requires, and
// writes it in the clear before that: REC_HDR + 2 bytes in the clear, and
// CH_ALERT_RECORD_LEN sealed.
//
// Each case reads the one record the failing end emitted, opens it with a
// copy of the key that reads it where it is sealed, hands it to the other
// end, and requires that end to report it through ch_alert_received and
// to emit nothing back (§6.2). The cases sit on both sides of each end's
// write key:
//
// - The client installs its write key right after the ServerHello. It
//   refuses, in the clear, a ServerHello whose key share gives an
//   all-zero x25519 secret, the last check before that key. It refuses,
//   sealed, a first protected record whose tag does not verify, the first
//   check after it, and a CertificateVerify that fails its pin.
// - The server installs its write key right after it has sent its
//   ServerHello. It refuses, in the clear, a first message that is not a
//   ClientHello, and a ClientHello whose key share gives an all-zero
//   x25519 secret, the last check before that key, after its ServerHello
//   is out. It fails sealed when its sink fails the EncryptedExtensions,
//   the first record that key seals, and under its application write key
//   when its sink fails the NewSessionTicket and when a client Finished's
//   tag does not verify.
//
// Included by test/tcp_nonblocking_loop_test.c after the handshake helpers.
#ifndef CH_TEST_TCP_NONBLOCKING_FAILURE_ALERT_TESTS_H
#define CH_TEST_TCP_NONBLOCKING_FAILURE_ALERT_TESTS_H

#include "tcp_nonblocking_record_end_tests.h"

// Moves r past a hello's fields up to its first extension. Returns the
// message type, HS_CLIENT_HELLO or HS_SERVER_HELLO.
static uint8_t skip_to_extensions(rbuf *r) {
    uint8_t type = rb_u8(r);
    rb_skip(r, 3 + 2 + 32); // the message length, legacy_version, random
    rb_skip(r, rb_u8(r));   // legacy_session_id, or its echo
    if (type == HS_CLIENT_HELLO) {
        rb_skip(r, rb_u16(r)); // cipher_suites
        rb_skip(r, rb_u8(r));  // legacy_compression_methods
    } else {
        rb_skip(r, 2 + 1); // cipher_suite, legacy_compression_method
    }
    rb_skip(r, 2); // the extensions' length
    return type;
}

// The offset from msg of the x25519 value in a hello's key share: the
// ServerHello's one share, or the ClientHello's first, which is the one
// this tree's raw client offers. An x25519 share is x25519 alone, and an
// X25519MLKEM768 share carries it in its last 32 bytes, after the ML-KEM
// part. 0 when msg carries no key share.
static size_t hello_x25519_at(const uint8_t *msg, size_t n) {
    rbuf r;
    rb_init(&r, msg, n);
    uint8_t type = skip_to_extensions(&r);
    while (rb_left(&r) > 0 && !r.err) {
        uint16_t ext = rb_u16(&r);
        size_t len = rb_u16(&r);
        const uint8_t *data = rb_bytes(&r, len);
        if (data == NULL || ext != EXT_KEY_SHARE) {
            continue;
        }
        rbuf share;
        rb_init(&share, data, len);
        // A ClientHello's shares follow a list length; each entry, and the
        // ServerHello's one, starts with its group.
        rb_skip(&share, type == HS_CLIENT_HELLO ? 2 + 2 : 2);
        size_t key_len = rb_u16(&share);
        const uint8_t *key = rb_bytes(&share, key_len);
        if (share.err || key_len < X25519_LEN) {
            return 0;
        }
        return (size_t)(key - msg) + key_len - X25519_LEN;
    }
    return 0;
}

// Zeroes the x25519 value in the hello the record at wire[0..) carries,
// which makes the other end's x25519 secret all zero.
static void zero_x25519_share(uint8_t *wire) {
    size_t record_len = record_at(wire, 0);
    size_t at = hello_x25519_at(wire + REC_HDR, record_len - REC_HDR);
    CHECK(at != 0);
    if (at != 0) {
        memset(wire + REC_HDR + at, 0, X25519_LEN);
    }
}

// Hands the failed client's alert record to the server, collected in
// calls of at most step bytes. The server must read it as the client's
// fatal alert and push nothing back. sealed says the record is sealed
// under the client's handshake write key, which the server's read key
// opens.
static void server_reads_client_alert(ch_record *client, ch_record *server, int sealed,
                                      uint8_t alert, size_t step) {
    CHECK(ch_record_state(client) == CH_ST_FAILED && ch_alert_sent(&client->t) == alert);
    uint8_t rec[64];
    size_t len = take_client_alert(client, rec, step);
    check_alert_record(rec, len, sealed ? &server->t.rd : NULL, alert);
    size_t pushed = records_pushed;
    size_t consumed = 0;
    CHECK(ch_srv_record_in(server, rec, len, &consumed) == CH_EPROTO);
    CHECK(ch_alert_received(&server->t) == alert && ch_alert_sent(&server->t) == 0);
    CHECK(records_pushed == pushed);
}

// Hands what the failed server pushed, to_client from off on, to the
// client in its handshake. The client must read the alert at its end as
// the server's fatal alert and stage nothing.
static void client_reads_server_alert(ch_record *client, size_t off, uint8_t alert) {
    size_t consumed = 0;
    CHECK(ch_record_in(client, to_client.bytes + off, to_client.len - off, &consumed) == CH_EPROTO);
    CHECK(ch_alert_received(&client->t) == alert && ch_alert_sent(&client->t) == 0);
    uint8_t staged[64];
    CHECK(take_client_alert(client, staged, sizeof staged) == 0);
}

// The client's last check before its write key: hsf_derive_handshake_secrets
// refuses the all-zero x25519 secret of the ServerHello's share with
// illegal_parameter, just before it installs the key.
static void client_refuses_server_share(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                                        const ch_cfg *scfg) {
    start_pair(client, server, ccfg, scfg);
    CHECK(client_to_server(client, server));
    zero_x25519_share(to_client.bytes);
    size_t consumed = 0;
    CHECK(ch_record_in(client, to_client.bytes, to_client.len, &consumed) == CH_EPROTO);
    server_reads_client_alert(client, server, 0, ALERT_ILLEGAL_PARAMETER, 64);
}

// The client's first check after its write key: the record after the
// ServerHello, the EncryptedExtensions, arrives with one bit of its tag
// flipped. The client refuses it with bad_record_mac, sealed under the key
// it has just installed, and hands the record over five bytes at a time.
static void client_refuses_first_protected_record(ch_record *client, ch_record *server,
                                                  const ch_cfg *ccfg, const ch_cfg *scfg) {
    start_pair(client, server, ccfg, scfg);
    CHECK(client_to_server(client, server));
    size_t hello_len = record_at(to_client.bytes, 0);
    CHECK(to_client.len > hello_len && to_client.bytes[hello_len] == REC_APPDATA);
    if (to_client.len <= hello_len) {
        return;
    }
    to_client.bytes[hello_len + record_at(to_client.bytes, hello_len) - 1] ^= 1;
    size_t consumed = 0;
    CHECK(ch_record_in(client, to_client.bytes, to_client.len, &consumed) == CH_EPROTO);
    server_reads_client_alert(client, server, 1, ALERT_BAD_RECORD_MAC, 5);
}

// A pin that is not this server's key. Without it the handshake the loop
// runs first would pass for a client that verified nothing, which is the
// reading a loopback invites: both halves are ours, so agreement is the
// cheap outcome. One flipped bit in the modulus makes rsa_pss_verify refuse
// the CertificateVerify, and the client must end dead with decrypt_error,
// sealed under its handshake write key, rather than connected.
static void client_refuses_wrong_pin(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                                     const ch_cfg *scfg) {
    static uint8_t wrong_pin[sizeof rsa_sign_2048_n];
    memcpy(wrong_pin, rsa_sign_2048_n, sizeof wrong_pin);
    wrong_pin[sizeof wrong_pin - 1] ^= 0x02; // the modulus stays odd
    ch_cfg pinned = *ccfg;
    pinned.server_pubkey = wrong_pin;
    (void)run_handshake(client, server, &pinned, scfg);
    CHECK(ch_alert_received(&client->t) == 0);
    server_reads_client_alert(client, server, 1, ALERT_DECRYPT_ERROR, 64);
    // The client refused CertificateVerify, which comes before the
    // server Finished, so it derived its handshake secrets and never its
    // application ones: two rows, both handshake labels.
    const uint8_t *unused = NULL;
    CHECK(logged_secret(0, CH_KEYLOG_CLIENT_HANDSHAKE, &unused) != NULL);
    CHECK(logged_secret(0, CH_KEYLOG_SERVER_HANDSHAKE, &unused) != NULL);
    CHECK(logged_secret(0, CH_KEYLOG_CLIENT_TRAFFIC, &unused) == NULL);
    CHECK(logged_secret(0, CH_KEYLOG_SERVER_TRAFFIC, &unused) == NULL);
    // A dead session exports nothing: the secret went with the wipe.
    uint8_t exported[SHA256_LEN];
    CHECK(ch_export(&client->t, "EXPORTER-Channel-Binding", NULL, 0, exported, sizeof exported) ==
          CH_EINVAL);
}

// A server refusal before any key: the first message is a ServerHello's
// type. The alert goes out alone, in the clear.
static void server_refuses_first_message(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                                         const ch_cfg *scfg) {
    static uint8_t wire[WIRE_MAX];
    start_pair(client, server, ccfg, scfg);
    size_t total = take_client_bytes(client, wire);
    wire[REC_HDR] = HS_SERVER_HELLO;
    size_t consumed = 0;
    CHECK(ch_srv_record_in(server, wire, total, &consumed) == CH_EPROTO);
    CHECK(ch_alert_sent(&server->t) == ALERT_UNEXPECTED_MESSAGE && records_pushed == 1);
    check_alert_record(to_client.bytes, to_client.len, NULL, ALERT_UNEXPECTED_MESSAGE);
    client_reads_server_alert(client, 0, ALERT_UNEXPECTED_MESSAGE);
}

// The server's last check before its write key: srv_derive_handshake_secrets
// refuses the all-zero x25519 secret of the ClientHello's share with
// illegal_parameter. The ServerHello went out before it, so the alert
// follows it in the clear, and the client reads that alert with its own
// keys installed.
static void server_refuses_client_share(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                                        const ch_cfg *scfg) {
    static uint8_t wire[WIRE_MAX];
    start_pair(client, server, ccfg, scfg);
    size_t total = take_client_bytes(client, wire);
    zero_x25519_share(wire);
    size_t consumed = 0;
    CHECK(ch_srv_record_in(server, wire, total, &consumed) == CH_EPROTO);
    CHECK(ch_alert_sent(&server->t) == ALERT_ILLEGAL_PARAMETER && records_pushed == 2);
    size_t hello_len = record_at(to_client.bytes, 0);
    CHECK(to_client.bytes[0] == REC_HANDSHAKE && to_client.len > hello_len);
    check_alert_record(to_client.bytes + hello_len, to_client.len - hello_len, NULL,
                       ALERT_ILLEGAL_PARAMETER);
    client_reads_server_alert(client, 0, ALERT_ILLEGAL_PARAMETER);
}

// The push failing_sink reports as failed, counted from 1, and the pushes
// it has seen. It hands every push to the loop's sink, the failed one
// included, as a socket does that writes the bytes and then reports an
// error. A record the client never received would leave it one sequence
// number behind the alert sealed after it, and no peer could open that.
static size_t failed_push;
static size_t pushes_seen;

static int failing_sink(void *io, const uint8_t *p, size_t n) {
    pushes_seen++;
    int rc = sink(io, p, n);
    return pushes_seen == failed_push ? -1 : rc;
}

// The server's first failure after its write key: the sink fails the
// EncryptedExtensions, the first record that key seals. A refused record
// is this side's failure and not the peer's, so the server records
// internal_error (RFC 9846 §6.2, rfc9846.txt:3979-3981). The alert goes
// through the same sink right after it, sealed under that key, and the
// client opens it with the read key the ServerHello gave it.
static void server_sink_fails_first_protected_record(ch_record *client, ch_record *server,
                                                     const ch_cfg *ccfg, const ch_cfg *scfg) {
    start_pair(client, server, ccfg, scfg);
    server->t.cfg.srv.on_record_out = failing_sink;
    failed_push = 2;
    pushes_seen = 0;
    CHECK(!client_to_server(client, server));
    uint8_t sent = ch_alert_sent(&server->t);
    CHECK(sent == ALERT_INTERNAL_ERROR && pushes_seen == 3 && records_pushed == 3);
    size_t hello_len = record_at(to_client.bytes, 0);
    size_t flight_len = hello_len + record_at(to_client.bytes, hello_len);
    size_t consumed = 0;
    CHECK(ch_record_in(client, to_client.bytes, flight_len, &consumed) == CH_OK);
    check_alert_record(to_client.bytes + flight_len, to_client.len - flight_len, &client->t.rd,
                       sent);
    client_reads_server_alert(client, flight_len, sent);
}

// A ticket key and a clock, so the server issues a NewSessionTicket once
// the client Finished verifies (srv_resume.h).
static const uint8_t failure_ticket_key[CH_SRV_TICKET_KEY_LEN] = {0x5a};

// Hands what the server pushed to the connected client through ch_read,
// which must read the server's fatal alert at the end and send nothing.
static void connected_client_reads_alert(ch_record *client, uint8_t alert) {
    memset(&held, 0, sizeof held);
    memcpy(held.bytes, to_client.bytes, to_client.len);
    held.len = to_client.len;
    client_sends = 0;
    client->t.cfg.send = client_send;
    client->t.cfg.recv = held_recv;
    uint8_t got[16];
    CHECK(ch_read(&client->t, got, sizeof got) == CH_EPROTO);
    CHECK(ch_alert_received(&client->t) == alert && ch_alert_sent(&client->t) == 0);
    CHECK(client_sends == 0);
}

// The server's one failure after it is connected: the sink fails the
// NewSessionTicket, the record the server pushes after the client
// Finished verifies. The failure records internal_error as every refused
// record does, and the alert goes through the same sink right after the
// ticket, sealed under the application write key. The connected client
// reads the ticket and then the alert.
static void server_sink_fails_ticket(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                                     const ch_cfg *scfg) {
    ch_cfg tickets = *scfg;
    tickets.srv.ticket_key = failure_ticket_key;
    tickets.srv.now_seconds = 1700000000U;
    start_pair(client, server, ccfg, &tickets);
    CHECK(client_to_server(client, server));
    CHECK(server_to_client(client));
    server->t.cfg.srv.on_record_out = failing_sink;
    failed_push = 1;
    pushes_seen = 0;
    CHECK(!client_to_server(client, server));
    CHECK(ch_record_state(client) == CH_ST_CONNECTED);
    CHECK(ch_record_state(server) == CH_ST_FAILED && pushes_seen == 2);
    CHECK(ch_alert_sent(&server->t) == ALERT_INTERNAL_ERROR);
    connected_client_reads_alert(client, ALERT_INTERNAL_ERROR);
}

// A server refusal under its application write key: the client Finished
// arrives with one bit of its tag flipped. The client is connected by then,
// reads the server's bad_record_mac with ch_read under the application read
// key it installed with its Finished, and sends nothing back.
static void server_refuses_client_finished(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                                           const ch_cfg *scfg) {
    static uint8_t wire[WIRE_MAX];
    start_pair(client, server, ccfg, scfg);
    CHECK(client_to_server(client, server));
    CHECK(server_to_client(client));
    size_t total = take_client_bytes(client, wire);
    CHECK(ch_record_state(client) == CH_ST_CONNECTED && total > 0);
    if (total == 0) {
        return;
    }
    wire[total - 1] ^= 1;
    size_t pushed = records_pushed;
    size_t consumed = 0;
    CHECK(ch_srv_record_in(server, wire, total, &consumed) == CH_EPROTO);
    CHECK(ch_alert_sent(&server->t) == ALERT_BAD_RECORD_MAC && records_pushed == pushed + 1);
    check_alert_record(to_client.bytes, to_client.len, &client->t.rd, ALERT_BAD_RECORD_MAC);
    connected_client_reads_alert(client, ALERT_BAD_RECORD_MAC);
}

static void test_failure_alerts(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                                const ch_cfg *scfg) {
    io_calls = 0;
    expect_refusal = 1;
    client_refuses_server_share(client, server, ccfg, scfg);
    client_refuses_first_protected_record(client, server, ccfg, scfg);
    client_refuses_wrong_pin(client, server, ccfg, scfg);
    server_refuses_first_message(client, server, ccfg, scfg);
    server_refuses_client_share(client, server, ccfg, scfg);
    server_sink_fails_first_protected_record(client, server, ccfg, scfg);
    server_sink_fails_ticket(client, server, ccfg, scfg);
    server_refuses_client_finished(client, server, ccfg, scfg);
    expect_refusal = 0;
    // INV-28: neither driver called a socket callback to emit its alert.
    CHECK(io_calls == 0);
}

#endif
