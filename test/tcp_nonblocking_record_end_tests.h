// RFC 9846 §5.1 between this tree's two tcp-nonblocking drivers: the
// message before a key change must end its record, and one that does not
// ends the connection with unexpected_message (rfc9846.txt:3464-3470,
// INV-39). Each case edits one record the other end wrote, adding bytes
// after the message that precedes a key change: the ServerHello and the
// server Finished the client reads, the ClientHello and the client
// Finished the server reads, and a KeyUpdate the connected server reads.
// The connected server also reads runs of KeyUpdates up to
// CH_KEY_UPDATE_RUN_MAX and one past it, one record a call.
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

// Seals pt as one record of type under the client's application write key
// and hands it to the connected server's ch_read, which reads it through
// server_recv, one record a call, as colibri's server reads. Returns the
// result. What the server sends goes to held, through server_send.
static int server_reads_record(ch_record *client, ch_record *server, uint8_t type,
                               const uint8_t *pt, size_t n) {
    memset(&to_server, 0, sizeof to_server);
    server->t.cfg.send = server_send;
    server->t.cfg.recv = server_recv;
    size_t out_len = 0;
    CHECK(rec_seal(&client->t.wr, type, pt, n, to_server.bytes, sizeof to_server.bytes, &out_len) ==
          0);
    to_server.len = out_len;
    uint8_t got[16];
    return ch_read(&server->t, got, sizeof got);
}

// Opens the record at held.bytes + at under reader, and returns where the
// next record starts.
static size_t open_held(rec_dir *reader, size_t at, uint8_t *type, uint8_t sent[16],
                        size_t *sent_len) {
    size_t end = at + record_at(held.bytes, at);
    CHECK(end <= held.len);
    CHECK(rec_open(reader, held.bytes + at, end - at, sent, 16, sent_len, type) == 0);
    return end;
}

// A connected pair whose server sends into held, and a copy of the
// server's write key, which opens what it sends.
static rec_dir start_held_server(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                                 const ch_cfg *scfg) {
    (void)run_handshake(client, server, ccfg, scfg);
    CHECK(ch_record_state(server) == CH_ST_CONNECTED);
    memset(&held, 0, sizeof held);
    server_sends = 0;
    return server->t.wr;
}

// The server's next write, after it read a request: the answer under the
// write key reader holds, then the write's data under the next key, which
// reader moves to with secret, the server's write secret before the write.
static size_t check_answer_then_data(ch_record *server, rec_dir *reader, uint8_t *secret,
                                     size_t at) {
    static const uint8_t answer[5] = {HS_KEY_UPDATE, 0, 0, 1, 0};
    size_t sends = server_sends;
    CHECK(ch_write(&server->t, (const uint8_t *)"ok", 2) == CH_OK && server_sends == sends + 2);
    uint8_t type = 0;
    uint8_t sent[16];
    size_t sent_len = 0;
    size_t next = open_held(reader, at, &type, sent, &sent_len);
    CHECK(type == REC_HANDSHAKE && sent_len == sizeof answer);
    CHECK(memcmp(sent, answer, sizeof answer) == 0 && next - at == CH_KEY_UPDATE_RECORD_LEN);
    rec_dir_update(secret, reader);
    next = open_held(reader, next, &type, sent, &sent_len);
    CHECK(type == REC_APPDATA && sent_len == 2 && next == held.len);
    return next;
}

// The record colibri sent a connected server: two KeyUpdates that each
// ask for an answer, in one record. One of them in its own record is the
// last valid shape: the read sends nothing, and the server's next write
// sends its one answer before the data.
static void test_server_key_update_ends_record(ch_record *client, ch_record *server,
                                               const ch_cfg *ccfg, const ch_cfg *scfg) {
    static const uint8_t two_requested[10] = {HS_KEY_UPDATE, 0, 0, 1, 1, HS_KEY_UPDATE, 0, 0, 1, 1};
    uint8_t type = 0;
    uint8_t sent[16];
    size_t sent_len = 0;

    rec_dir reader = start_held_server(client, server, ccfg, scfg);
    uint8_t secret[SHA256_LEN];
    memcpy(secret, server->t.wr_secret, sizeof secret);
    int rc = server_reads_record(client, server, REC_HANDSHAKE, two_requested, 5);
    CHECK(rc == CH_RECORD_AGAIN && ch_record_state(server) == CH_ST_CONNECTED);
    CHECK(server_sends == 0 && server->t.key_update_owed == 1);
    (void)check_answer_then_data(server, &reader, secret, 0);

    reader = start_held_server(client, server, ccfg, scfg);
    rc = server_reads_record(client, server, REC_HANDSHAKE, two_requested, sizeof two_requested);
    CHECK(rc == CH_EPROTO && ch_record_state(server) == CH_ST_FAILED && server_sends == 1);
    CHECK(open_held(&reader, 0, &type, sent, &sent_len) == held.len);
    CHECK(type == REC_ALERT && sent_len == 2 && sent[0] == 2);
    CHECK(sent[1] == ALERT_UNEXPECTED_MESSAGE && held.len == CH_ALERT_RECORD_LEN);
}

// Reads count KeyUpdates that each ask for an answer, one a call, as
// colibri's server reads them. Each read returns CH_RECORD_AGAIN, and the
// client's write key follows each KeyUpdate it sealed.
static void server_reads_requests(ch_record *client, ch_record *server, size_t count) {
    static const uint8_t requested[5] = {HS_KEY_UPDATE, 0, 0, 1, 1};
    for (size_t i = 0; i < count; i++) {
        CHECK(server_reads_record(client, server, REC_HANDSHAKE, requested, sizeof requested) ==
              CH_RECORD_AGAIN);
        rec_dir_update(client->t.wr_secret, &client->t.wr);
    }
}

// The run limit across reads, the shape colibri's server reads in
// (docs/decisions.md 138). Two full runs of requests, each ended by a data
// record of one byte, send nothing and owe one answer, which the next
// write sends. Then a third full run, and a write that sends the answer.
// The server's own KeyUpdate ends no run, so one more KeyUpdate from the
// client fails the session with CH_KEY_UPDATE_LIMIT and an
// unexpected_message alert.
static void test_server_key_update_run(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                                       const ch_cfg *scfg) {
    rec_dir reader = start_held_server(client, server, ccfg, scfg);
    uint8_t secret[SHA256_LEN];
    memcpy(secret, server->t.wr_secret, sizeof secret);
    for (int run = 0; run < 2; run++) {
        server_reads_requests(client, server, CH_KEY_UPDATE_RUN_MAX);
        CHECK(server->t.key_update_run == CH_KEY_UPDATE_RUN_MAX);
        CHECK(server_reads_record(client, server, REC_APPDATA, (const uint8_t *)"a", 1) == 1);
    }
    CHECK(server_sends == 0 && server->t.key_update_run == 0);
    size_t at = check_answer_then_data(server, &reader, secret, 0);

    server_reads_requests(client, server, CH_KEY_UPDATE_RUN_MAX);
    at = check_answer_then_data(server, &reader, secret, at);
    CHECK(server->t.key_update_run == CH_KEY_UPDATE_RUN_MAX);
    static const uint8_t update[5] = {HS_KEY_UPDATE, 0, 0, 1, 0};
    int rc = server_reads_record(client, server, REC_HANDSHAKE, update, sizeof update);
    CHECK(rc == CH_KEY_UPDATE_LIMIT && ch_record_state(server) == CH_ST_FAILED);
    CHECK(ch_alert_sent(&server->t) == ALERT_UNEXPECTED_MESSAGE);
    uint8_t type = 0;
    uint8_t sent[16];
    size_t sent_len = 0;
    CHECK(open_held(&reader, at, &type, sent, &sent_len) == held.len);
    CHECK(type == REC_ALERT && sent_len == 2 && sent[1] == ALERT_UNEXPECTED_MESSAGE);
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
    test_server_key_update_run(client, server, ccfg, scfg);
}

#endif
