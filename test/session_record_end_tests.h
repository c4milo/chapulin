// RFC 9846 §5.1 on a connected session: a KeyUpdate changes the read
// key, so it must end its record, and a record with bytes after one ends
// the connection with unexpected_message (rfc9846.txt:3464-3470, INV-39).
// ch_read runs the same code in either role, so these cases hold for a
// server's session too, and bin/tcp_nonblocking_loop_test repeats the
// record colibri sent to a real server. Included by session_tests.h after
// the mock helpers exist; not a standalone translation unit.
#ifndef CH_SESSION_RECORD_END_TESTS_H
#define CH_SESSION_RECORD_END_TESTS_H

// One connected session, the peer key its records arrive under, and the
// key that opens what the session sends back. peer_secret follows the
// peer's KeyUpdates, so a case moves the peer to its next key with
// rec_dir_update(peer_secret, &peer).
typedef struct {
    mock_io m;
    ch_tls t;
    rec_dir peer;
    uint8_t peer_secret[SHA256_LEN];
    rec_dir reader;
} record_end_case;

static void record_end_start(record_end_case *c) {
    static uint8_t rxbuf[1024];
    memset(c, 0, sizeof *c);
    ch_rand_bytes(c->peer_secret, sizeof c->peer_secret);
    rec_dir_init(&c->peer, c->peer_secret);
    uint8_t wr_secret[SHA256_LEN];
    mock_session(&c->t, &c->m, rxbuf, sizeof rxbuf, c->peer_secret, wr_secret);
    rec_dir_init(&c->reader, wr_secret);
}

// A refused record: ch_read returns CH_EPROTO, the session is dead, and
// the one record it sent is an unexpected_message alert under the write
// key it started with, so no KeyUpdate answer and no rekey came first.
static void check_refused(record_end_case *c, int rc) {
    CHECK(rc == CH_EPROTO && c->t.state == CH_ST_FAILED);
    uint8_t pt[16];
    size_t pt_len = 0;
    uint8_t type = 0;
    size_t at = mock_pop_client_record(&c->m, 0, &c->reader, pt, sizeof pt, &pt_len, &type);
    CHECK(type == REC_ALERT && pt_len == 2 && pt[0] == 2 && pt[1] == ALERT_UNEXPECTED_MESSAGE);
    CHECK(at == c->m.tx_len);
}

// The one record an accepted update_requested gets back: a KeyUpdate
// with update_not_requested, under the write key the session started
// with, and nothing after it.
static void check_one_answer(record_end_case *c) {
    uint8_t pt[16];
    size_t pt_len = 0;
    uint8_t type = 0;
    size_t at = mock_pop_client_record(&c->m, 0, &c->reader, pt, sizeof pt, &pt_len, &type);
    const uint8_t answer[5] = {HS_KEY_UPDATE, 0, 0, 1, 0};
    CHECK(type == REC_HANDSHAKE && pt_len == sizeof answer && memcmp(pt, answer, pt_len) == 0);
    CHECK(at == c->m.tx_len && at == CH_KEY_UPDATE_RECORD_LEN);
}

static void test_key_update_ends_record(void) {
    static const uint8_t update[5] = {HS_KEY_UPDATE, 0, 0, 1, 0};
    static const uint8_t requested[6] = {HS_KEY_UPDATE, 0, 0, 1, 1, 0};
    static const uint8_t two_requested[10] = {HS_KEY_UPDATE, 0, 0, 1, 1, HS_KEY_UPDATE, 0, 0, 1, 1};
    const uint8_t hola[4] = {'h', 'o', 'l', 'a'};
    uint8_t out[16];
    record_end_case c;

    // The last valid record: the KeyUpdate ends it. The session answers
    // the request and reads the data under the key the peer moved to.
    record_end_start(&c);
    mock_push(&c.m, &c.peer, REC_HANDSHAKE, requested, 5);
    rec_dir_update(c.peer_secret, &c.peer);
    mock_push(&c.m, &c.peer, REC_APPDATA, hola, sizeof hola);
    CHECK(ch_read(&c.t, out, sizeof out) == 4 && memcmp(out, hola, 4) == 0);
    CHECK(c.t.state == CH_ST_CONNECTED);
    check_one_answer(&c);

    // The first invalid one: the same record and one byte more. The
    // session refuses before it rekeys or answers.
    record_end_start(&c);
    mock_push(&c.m, &c.peer, REC_HANDSHAKE, requested, sizeof requested);
    check_refused(&c, ch_read(&c.t, out, sizeof out));

    // The record colibri sent: two KeyUpdates that each ask for an
    // answer. Neither is answered.
    record_end_start(&c);
    mock_push(&c.m, &c.peer, REC_HANDSHAKE, two_requested, sizeof two_requested);
    check_refused(&c, ch_read(&c.t, out, sizeof out));

    // A KeyUpdate and then the first byte of a ticket, whose other bytes
    // come under the next key. Read on, the ticket would span the key
    // change and the data after it would arrive.
    uint8_t ticket[64];
    static const uint8_t empty_exts[2] = {0, 0};
    size_t ticket_len = build_ticket_msg(ticket, sizeof ticket, 3600, 2, empty_exts, 2);
    uint8_t first[6];
    memcpy(first, update, sizeof update);
    first[5] = ticket[0];
    record_end_start(&c);
    mock_push(&c.m, &c.peer, REC_HANDSHAKE, first, sizeof first);
    rec_dir_update(c.peer_secret, &c.peer);
    mock_push(&c.m, &c.peer, REC_HANDSHAKE, ticket + 1, ticket_len - 1);
    mock_push(&c.m, &c.peer, REC_APPDATA, hola, sizeof hola);
    check_refused(&c, ch_read(&c.t, out, sizeof out));
    CHECK(c.m.tickets == 0);

    // A KeyUpdate split across two records under one key ends the second
    // record, which is legal.
    record_end_start(&c);
    mock_push(&c.m, &c.peer, REC_HANDSHAKE, requested, 2);
    mock_push(&c.m, &c.peer, REC_HANDSHAKE, requested + 2, 3);
    rec_dir_update(c.peer_secret, &c.peer);
    mock_push(&c.m, &c.peer, REC_APPDATA, hola, sizeof hola);
    CHECK(ch_read(&c.t, out, sizeof out) == 4 && c.t.state == CH_ST_CONNECTED);
    check_one_answer(&c);

    // So is a ticket and then a KeyUpdate that ends the record.
    uint8_t both[64 + 5];
    memcpy(both, ticket, ticket_len);
    memcpy(both + ticket_len, requested, 5);
    record_end_start(&c);
    mock_push(&c.m, &c.peer, REC_HANDSHAKE, both, ticket_len + 5);
    rec_dir_update(c.peer_secret, &c.peer);
    mock_push(&c.m, &c.peer, REC_APPDATA, hola, sizeof hola);
    CHECK(ch_read(&c.t, out, sizeof out) == 4 && c.t.state == CH_ST_CONNECTED);
    CHECK(c.m.tickets == 1);
    check_one_answer(&c);
}

#endif
