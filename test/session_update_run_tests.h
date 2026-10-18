// The KeyUpdates a peer sends a connected session in a row, over the mock
// transport (docs/decisions.md 138). A run of requests gets one answer, and
// the next ch_write sends it before its data record (RFC 9846 §4.7.3,
// rfc9846.txt:3367-3373). A run holds at most CH_KEY_UPDATE_RUN_MAX
// (session.h), and a record of application data with a byte or more ends
// it. ch_read runs the same code in either role, and
// bin/tcp_nonblocking_loop_test repeats the limit with one record a call.
// Included by session_tests.h after the mock helpers and
// session_post_tests.h's build_ticket_msg exist; not a standalone
// translation unit.
#ifndef CH_SESSION_UPDATE_RUN_TESTS_H
#define CH_SESSION_UPDATE_RUN_TESTS_H

// One connected session, the peer that writes to it, and the key that
// opens what the session sends. The peer's key follows its own
// KeyUpdates.
typedef struct {
    mock_io m;
    ch_tls t;
    rec_dir peer;
    uint8_t peer_secret[SHA256_LEN];
    rec_dir reader;
    uint8_t reader_secret[SHA256_LEN];
} update_run_case;

static void update_run_start(update_run_case *c) {
    static uint8_t rxbuf[1024];
    memset(c, 0, sizeof *c);
    ch_rand_bytes(c->peer_secret, sizeof c->peer_secret);
    TEST_CPU_DIR(c->peer);
    rec_dir_init(&c->peer, c->peer_secret);
    mock_session(&c->t, &c->m, rxbuf, sizeof rxbuf, c->peer_secret, c->reader_secret);
    TEST_CPU_DIR(c->reader);
    rec_dir_init(&c->reader, c->reader_secret);
}

// Pushes count KeyUpdates with request_update request, each in a record
// of its own under the peer's key, and moves the peer to its next key
// after each.
static void update_run_push(update_run_case *c, size_t count, uint8_t request) {
    const uint8_t update[5] = {HS_KEY_UPDATE, 0, 0, 1, request};
    for (size_t i = 0; i < count; i++) {
        mock_push(&c->m, &c->peer, REC_HANDSHAKE, update, sizeof update);
        rec_dir_update(c->peer_secret, &c->peer);
    }
}

// A read that fails: rc, a dead session, and one record sent, the fatal
// alert under the write key the session started with.
static void check_run_read_fails(update_run_case *c, int rc, uint8_t alert) {
    uint8_t out[16];
    CHECK(ch_read(&c->t, out, sizeof out) == rc);
    CHECK(c->t.state == CH_ST_FAILED && ch_alert_sent(&c->t) == alert);
    uint8_t pt[16];
    size_t pt_len = 0;
    uint8_t type = 0;
    size_t at = mock_pop_client_record(&c->m, 0, &c->reader, pt, sizeof pt, &pt_len, &type);
    CHECK(type == REC_ALERT && pt_len == 2 && pt[0] == 2 && pt[1] == alert);
    CHECK(at == c->m.tx_len && c->m.sends == 1);
}

// The read that meets one KeyUpdate past a full run: CH_KEY_UPDATE_LIMIT
// and unexpected_message.
static void check_run_refused(update_run_case *c) {
    check_run_read_fails(c, CH_KEY_UPDATE_LIMIT, ALERT_UNEXPECTED_MESSAGE);
}

// A full run of requests, then data. Each KeyUpdate moved the read key,
// since the data opens under the peer's last key, and the read sent
// nothing. The next write sends one KeyUpdate and then its data, and the
// write after it sends its data alone.
static void test_key_update_one_answer(void) {
    update_run_case c;
    update_run_start(&c);
    update_run_push(&c, CH_KEY_UPDATE_RUN_MAX, 1);
    mock_push(&c.m, &c.peer, REC_APPDATA, (const uint8_t *)"hola", 4);
    uint8_t out[16];
    CHECK(ch_read(&c.t, out, sizeof out) == 4 && memcmp(out, "hola", 4) == 0);
    CHECK(c.m.sends == 0 && c.t.key_update_owed == 1 && c.t.key_update_run == 0);

    CHECK(ch_write(&c.t, (const uint8_t *)"si", 2) == CH_OK);
    CHECK(c.m.sends == 2 && c.t.send_epochs == 1 && c.t.key_update_owed == 0);
    uint8_t pt[16];
    size_t pt_len = 0;
    uint8_t type = 0;
    size_t at = mock_pop_client_record(&c.m, 0, &c.reader, pt, sizeof pt, &pt_len, &type);
    const uint8_t answer[5] = {HS_KEY_UPDATE, 0, 0, 1, 0};
    CHECK(type == REC_HANDSHAKE && pt_len == sizeof answer && memcmp(pt, answer, pt_len) == 0);
    rec_dir_update(c.reader_secret, &c.reader);
    at = mock_pop_client_record(&c.m, at, &c.reader, pt, sizeof pt, &pt_len, &type);
    CHECK(type == REC_APPDATA && pt_len == 2 && memcmp(pt, "si", 2) == 0);

    CHECK(ch_write(&c.t, (const uint8_t *)"no", 2) == CH_OK);
    CHECK(c.m.sends == 3 && c.t.send_epochs == 1);
    at = mock_pop_client_record(&c.m, at, &c.reader, pt, sizeof pt, &pt_len, &type);
    CHECK(type == REC_APPDATA && pt_len == 2 && at == c.m.tx_len);
}

// A session that owes the answer and closes sends its close_notify alone,
// under the write key it started with: RFC 9846 §4.7.3 owes the answer
// before application data, and none follows the close.
static void test_key_update_owed_at_close(void) {
    update_run_case c;
    update_run_start(&c);
    update_run_push(&c, 1, 1);
    mock_push(&c.m, &c.peer, REC_APPDATA, (const uint8_t *)"x", 1);
    uint8_t out[16];
    CHECK(ch_read(&c.t, out, sizeof out) == 1 && c.t.key_update_owed == 1);
    ch_close(&c.t);
    uint8_t pt[16];
    size_t pt_len = 0;
    uint8_t type = 0;
    size_t at = mock_pop_client_record(&c.m, 0, &c.reader, pt, sizeof pt, &pt_len, &type);
    CHECK(type == REC_ALERT && pt_len == 2 && pt[0] == 1 && pt[1] == ALERT_CLOSE_NOTIFY);
    CHECK(at == c.m.tx_len && c.m.sends == 1 && at == CH_ALERT_RECORD_LEN);
}

// A sender at the KeyUpdate epoch cap ignores update_requested instead of
// answering it (RFC 9846 §4.7.3, rfc9846.txt:3405-3408). The read key
// still moves, since the data after the request opens under the peer's
// next key. No answer is owed, and the next write sends its data record
// alone.
static void test_key_update_at_epoch_cap(void) {
    update_run_case c;
    update_run_start(&c);
    c.t.send_epochs = 0xffffffffffffULL;
    update_run_push(&c, 1, 1);
    mock_push(&c.m, &c.peer, REC_APPDATA, (const uint8_t *)"hola", 4);
    uint8_t out[16];
    CHECK(ch_read(&c.t, out, sizeof out) == 4 && memcmp(out, "hola", 4) == 0);
    CHECK(c.m.sends == 0 && c.t.key_update_owed == 0);
    CHECK(ch_write(&c.t, (const uint8_t *)"x", 1) == CH_OK);
    CHECK(c.m.sends == 1 && c.m.sent == REC_OVERHEAD + 1);
    CHECK(c.t.send_epochs == 0xffffffffffffULL);
}

// The limit at its boundary, and what ends a run. CH_KEY_UPDATE_RUN_MAX
// KeyUpdates in a row are read, and one more is refused. A data record of
// one byte ends a run, so a second full run after it is read too. An
// empty data record, a user_canceled alert and a NewSessionTicket do not
// end one, so the KeyUpdate after any of them is still one too many.
static void test_key_update_run(void) {
    uint8_t out[16];
    update_run_case c;

    update_run_start(&c);
    update_run_push(&c, CH_KEY_UPDATE_RUN_MAX, 0);
    mock_push(&c.m, &c.peer, REC_APPDATA, (const uint8_t *)"a", 1);
    CHECK(ch_read(&c.t, out, sizeof out) == 1 && c.t.key_update_run == 0);
    update_run_push(&c, CH_KEY_UPDATE_RUN_MAX, 0);
    mock_push(&c.m, &c.peer, REC_APPDATA, (const uint8_t *)"b", 1);
    CHECK(ch_read(&c.t, out, sizeof out) == 1 && out[0] == 'b');
    CHECK(c.t.state == CH_ST_CONNECTED && c.m.sends == 0);

    update_run_start(&c);
    update_run_push(&c, CH_KEY_UPDATE_RUN_MAX + 1, 0);
    check_run_refused(&c);

    update_run_start(&c);
    update_run_push(&c, CH_KEY_UPDATE_RUN_MAX, 1);
    mock_push(&c.m, &c.peer, REC_APPDATA, (const uint8_t *)"", 0);
    update_run_push(&c, 1, 1);
    check_run_refused(&c);

    // RFC 9846 §6.1 has the reader go on past a user_canceled alert, and
    // ch_read reads past it. It carries no data, so the run goes on too.
    static const uint8_t user_canceled[2] = {1, ALERT_USER_CANCELED};
    update_run_start(&c);
    update_run_push(&c, CH_KEY_UPDATE_RUN_MAX, 0);
    mock_push(&c.m, &c.peer, REC_ALERT, user_canceled, sizeof user_canceled);
    update_run_push(&c, 1, 0);
    check_run_refused(&c);

    uint8_t ticket[64];
    static const uint8_t empty_exts[2] = {0, 0};
    size_t ticket_len = build_ticket_msg(ticket, sizeof ticket, 3600, 2, empty_exts, 2);
    update_run_start(&c);
    update_run_push(&c, CH_KEY_UPDATE_RUN_MAX, 0);
    mock_push(&c.m, &c.peer, REC_HANDSHAKE, ticket, ticket_len);
    update_run_push(&c, 1, 0);
    check_run_refused(&c);
    CHECK(c.m.tickets == 1);
}

// The KeyUpdate after a full run meets the parser's other refusals first,
// each with CH_EPROTO and its own alert: decode_error for a body that is
// not one byte and illegal_parameter for a request_update of 2 (INV-14),
// and unexpected_message for a byte after the KeyUpdate in its record
// (INV-39). The run limit refuses only a KeyUpdate that those three admit.
static void test_key_update_run_refusal_order(void) {
    static const uint8_t two_byte_body[6] = {HS_KEY_UPDATE, 0, 0, 2, 0, 0};
    static const uint8_t request_two[5] = {HS_KEY_UPDATE, 0, 0, 1, 2};
    static const uint8_t byte_after[6] = {HS_KEY_UPDATE, 0, 0, 1, 0, 0};
    static const struct {
        const uint8_t *msg;
        size_t len;
        uint8_t alert;
    } refused[3] = {
        {two_byte_body, sizeof two_byte_body, ALERT_DECODE_ERROR      },
        {request_two,   sizeof request_two,   ALERT_ILLEGAL_PARAMETER },
        {byte_after,    sizeof byte_after,    ALERT_UNEXPECTED_MESSAGE},
    };
    for (size_t i = 0; i < 3; i++) {
        update_run_case c;
        update_run_start(&c);
        update_run_push(&c, CH_KEY_UPDATE_RUN_MAX, 0);
        mock_push(&c.m, &c.peer, REC_HANDSHAKE, refused[i].msg, refused[i].len);
        check_run_read_fails(&c, CH_EPROTO, refused[i].alert);
    }
}

// One ch_read fails with CH_EPROTO once it has read CH_QUIET_CAP records
// that give no data (tls.c). A full run and the KeyUpdate after it leave
// room for CH_QUIET_CAP - CH_KEY_UPDATE_RUN_MAX - 1 other such records in
// the same call. With that many empty data records among the KeyUpdates,
// the run limit refuses the next KeyUpdate. With one more, the quiet cap
// fails the read first, with CH_EPROTO and the same alert.
static void test_key_update_run_quiet_cap(void) {
    const size_t room = CH_QUIET_CAP - CH_KEY_UPDATE_RUN_MAX - 1;
    for (size_t empty = room; empty <= room + 1; empty++) {
        update_run_case c;
        update_run_start(&c);
        for (size_t i = 0; i < CH_KEY_UPDATE_RUN_MAX; i++) {
            update_run_push(&c, 1, 1);
            if (i < empty) {
                mock_push(&c.m, &c.peer, REC_APPDATA, (const uint8_t *)"", 0);
            }
        }
        update_run_push(&c, 1, 1);
        int rc = empty == room ? CH_KEY_UPDATE_LIMIT : CH_EPROTO;
        check_run_read_fails(&c, rc, ALERT_UNEXPECTED_MESSAGE);
    }
}

#endif
