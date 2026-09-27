// RFC 9846 §5.1 between this tree's two tcp-nonblocking drivers: the
// message before a key change must end its record, and one that does not
// ends the connection with unexpected_message (rfc9846.txt:3464-3470,
// INV-39). Each case edits one record the other end wrote, adding bytes
// after the message that precedes a key change: the ServerHello and the
// server Finished the client reads, the ClientHello and the client
// Finished the server reads, and a KeyUpdate the connected server reads.
// Each runs twice, with 0 bytes added and with 1, so the edit is shown to
// be sound before the byte it adds is shown to be refused, and each
// refusal's alert record is read back: in the clear before the refusing
// end's write key, and sealed under that key after. Included by
// test/tcp_nonblocking_loop_test.c; it edits records through
// test/record_edit.h, and it reuses tcp_nonblocking_close_tests.h's
// to_server, server_recv and server_send, and the held records they share
// with tcp_nonblocking_read_tests.h.
#ifndef CH_TEST_TCP_NONBLOCKING_RECORD_END_TESTS_H
#define CH_TEST_TCP_NONBLOCKING_RECORD_END_TESTS_H

#include "record_edit.h"
#include "tcp_nonblocking_close_tests.h"

// Everything the client owes, taken out of its staging array.
static size_t take_client_bytes(ch_record *client, uint8_t *wire) {
    size_t total = 0;
    size_t n = 0;
    do {
        CHECK(ch_record_out(client, wire + total, WIRE_MAX - total, &n) == CH_OK);
        total += n;
    } while (n > 0);
    return total;
}

// What a failed client staged, collected into out in calls of at most
// step bytes until ch_record_out answers CH_EINVAL, which it must do on
// the call after the last byte and on no call before. Returns the bytes
// collected, 0 when the client staged nothing.
static size_t take_client_alert(ch_record *client, uint8_t out[64], size_t step) {
    size_t total = 0;
    size_t calls = 0;
    int rc = CH_OK;
    while (rc == CH_OK && calls < 64) {
        size_t room = 64 - total < step ? 64 - total : step;
        size_t n = 0;
        rc = ch_record_out(client, out + total, room, &n);
        calls++;
        CHECK(rc != CH_OK || (n > 0 && n <= room));
        total += rc == CH_OK ? n : 0;
    }
    CHECK(rc == CH_EINVAL && calls == (total + step - 1) / step + 1);
    return total;
}

// One alert record of len bytes at rec, as the failing end emitted it.
// With reader NULL it is in the clear: REC_HDR + 2 bytes holding the fatal
// alert. Otherwise it is CH_ALERT_RECORD_LEN bytes that open under a copy
// of reader to exactly 2 bytes of plaintext, that alert. The copy leaves
// the key it was taken from where it was.
static void check_alert_record(const uint8_t *rec, size_t len, const rec_dir *reader,
                               uint8_t alert) {
    if (reader == NULL) {
        static const uint8_t header[REC_HDR] = {REC_ALERT, 0x03, 0x03, 0, 2};
        CHECK(len == REC_HDR + 2 && memcmp(rec, header, REC_HDR) == 0);
        CHECK(len == REC_HDR + 2 && rec[REC_HDR] == 2 && rec[REC_HDR + 1] == alert);
        return;
    }
    CHECK(len == CH_ALERT_RECORD_LEN);
    rec_dir copy = *reader;
    uint8_t pt[CH_ALERT_RECORD_LEN];
    size_t pt_len = 0;
    uint8_t type = 0;
    CHECK(rec_open(&copy, rec, len, pt, sizeof pt, &pt_len, &type) == 0);
    CHECK(type == REC_ALERT && pt_len == 2 && pt[0] == 2 && pt[1] == alert);
}

// Two fresh sessions with the ClientHello not yet taken.
static void start_pair(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                       const ch_cfg *scfg) {
    to_client.len = 0;
    records_pushed = 0;
    logged_count = 0;
    CHECK(ch_srv_record_init(server, scfg) == CH_OK);
    CHECK(ch_record_init(client, ccfg) == CH_OK);
}

// What a refusal leaves: the call's result, the alert it chose, and a
// dead session.
static void check_refused_with(const ch_record *r, int rc) {
    CHECK(rc == CH_EPROTO);
    CHECK(ch_alert_sent(&r->t) == ALERT_UNEXPECTED_MESSAGE);
    CHECK(ch_record_state(r) == CH_ST_FAILED);
}

// The client reads the ServerHello, and then, after its key change, the
// server's Finished. The one after_finished names has extra zero bytes
// after it in its record.
static void client_reads_flight(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                                const ch_cfg *scfg, int after_finished, size_t extra) {
    start_pair(client, server, ccfg, scfg);
    CHECK(client_to_server(client, server));
    if (after_finished) {
        reseal_last_record(to_client.bytes, &to_client.len, WIRE_MAX, server->hs.s_hs, extra);
    } else {
        grow_first_record(to_client.bytes, &to_client.len, WIRE_MAX, extra);
    }
    size_t consumed = 0;
    int rc = ch_record_in(client, to_client.bytes, to_client.len, &consumed);
    if (extra > 0) {
        check_refused_with(client, rc);
        // A ServerHello is refused before the client's write key, so its
        // alert goes in the clear, and a server Finished after it, sealed
        // under the handshake write key the server reads with.
        uint8_t alert[64];
        size_t alert_len = take_client_alert(client, alert, sizeof alert);
        check_alert_record(alert, alert_len, after_finished ? &server->t.rd : NULL,
                           ALERT_UNEXPECTED_MESSAGE);
        return;
    }
    CHECK(rc == CH_OK && consumed == to_client.len);
    to_client.len = 0;
    CHECK(client_to_server(client, server));
    CHECK(ch_record_state(client) == CH_ST_CONNECTED);
    CHECK(ch_record_state(server) == CH_ST_CONNECTED);
}

// The server reads the ClientHello, and then, after its key change, the
// client Finished. The one after_finished names has extra zero bytes
// after it in its record.
static void server_reads_client(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                                const ch_cfg *scfg, int after_finished, size_t extra) {
    static uint8_t wire[WIRE_MAX];
    start_pair(client, server, ccfg, scfg);
    if (after_finished) {
        CHECK(client_to_server(client, server));
        CHECK(server_to_client(client));
    }
    size_t total = take_client_bytes(client, wire);
    if (after_finished) {
        reseal_last_record(wire, &total, WIRE_MAX, server->hs.c_hs, extra);
    } else {
        grow_first_record(wire, &total, WIRE_MAX, extra);
    }
    size_t pushed = records_pushed;
    size_t before = to_client.len;
    size_t consumed = 0;
    int rc = ch_srv_record_in(server, wire, total, &consumed);
    if (extra > 0) {
        check_refused_with(server, rc);
        // A refused ClientHello gets no ServerHello, and a refused client
        // Finished gets no ticket: the one record pushed is the alert, in
        // the clear before the server's write key and sealed under its
        // application write key after its Finished, which the connected
        // client reads with.
        CHECK(records_pushed == pushed + 1);
        check_alert_record(to_client.bytes + before, to_client.len - before,
                           after_finished ? &client->t.rd : NULL, ALERT_UNEXPECTED_MESSAGE);
        return;
    }
    CHECK(rc == CH_OK && consumed == total);
    if (after_finished) {
        CHECK(ch_record_state(server) == CH_ST_CONNECTED);
    } else {
        CHECK(records_pushed > pushed);
    }
}

// Seals pt as one record under the client's application write key, hands
// it to the connected server's ch_read, and returns the result and the
// one record the server sent, opened under the write key it held before.
static int server_reads_update(ch_record *client, ch_record *server, const uint8_t *pt, size_t n,
                               uint8_t *sent_type, uint8_t sent[16], size_t *sent_len) {
    memset(&held, 0, sizeof held);
    memset(&to_server, 0, sizeof to_server);
    server_sends = 0;
    server->t.cfg.send = server_send;
    server->t.cfg.recv = server_recv;
    size_t out_len = 0;
    CHECK(rec_seal(&client->t.wr, REC_HANDSHAKE, pt, n, to_server.bytes, sizeof to_server.bytes,
                   &out_len) == 0);
    to_server.len = out_len;
    rec_dir reader = server->t.wr;
    uint8_t got[16];
    int rc = ch_read(&server->t, got, sizeof got);
    CHECK(server_sends == 1 && held.len == record_at(held.bytes, 0));
    CHECK(rec_open(&reader, held.bytes, held.len, sent, 16, sent_len, sent_type) == 0);
    return rc;
}

// The record colibri sent a connected server: two KeyUpdates that each
// ask for an answer, in one record. One of them in its own record is the
// last valid shape and gets its one answer.
static void test_server_key_update_ends_record(ch_record *client, ch_record *server,
                                               const ch_cfg *ccfg, const ch_cfg *scfg) {
    static const uint8_t two_requested[10] = {HS_KEY_UPDATE, 0, 0, 1, 1, HS_KEY_UPDATE, 0, 0, 1, 1};
    static const uint8_t answer[5] = {HS_KEY_UPDATE, 0, 0, 1, 0};
    uint8_t type = 0;
    uint8_t sent[16];
    size_t sent_len = 0;

    (void)run_handshake(client, server, ccfg, scfg);
    CHECK(ch_record_state(server) == CH_ST_CONNECTED);
    int rc = server_reads_update(client, server, two_requested, 5, &type, sent, &sent_len);
    CHECK(rc == CH_RECORD_AGAIN && ch_record_state(server) == CH_ST_CONNECTED);
    CHECK(type == REC_HANDSHAKE && sent_len == sizeof answer);
    CHECK(memcmp(sent, answer, sizeof answer) == 0 && held.len == CH_KEY_UPDATE_RECORD_LEN);

    (void)run_handshake(client, server, ccfg, scfg);
    rc = server_reads_update(client, server, two_requested, sizeof two_requested, &type, sent,
                             &sent_len);
    CHECK(rc == CH_EPROTO && ch_record_state(server) == CH_ST_FAILED);
    CHECK(type == REC_ALERT && sent_len == 2 && sent[0] == 2);
    CHECK(sent[1] == ALERT_UNEXPECTED_MESSAGE && held.len == CH_ALERT_RECORD_LEN);
}

static void test_record_end(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                            const ch_cfg *scfg) {
    for (size_t extra = 0; extra <= 1; extra++) {
        client_reads_flight(client, server, ccfg, scfg, 0, extra);
        client_reads_flight(client, server, ccfg, scfg, 1, extra);
        server_reads_client(client, server, ccfg, scfg, 0, extra);
        server_reads_client(client, server, ccfg, scfg, 1, extra);
    }
    test_server_key_update_ends_record(client, server, ccfg, scfg);
}

#endif
