// What a connected session does with an alert record, and what alert.h's
// two calls report after it, over the mock transport. Included by
// session_tests.h after the mock helpers exist; not a standalone
// translation unit.
//
// The peer's fatal alert ends the session and gets no answer (RFC 9846
// §6.2, rfc9846.txt:3890-3893): the read returns CH_EPROTO, sends nothing,
// wipes the keys and names the alert in ch_alert_received, whatever the
// level byte says. A record of the alert type that is not one 2-byte
// alert is answered with decode_error, which ch_alert_sent names, and so
// is every other failure tlsi_fail meets.
#ifndef CH_TEST_SESSION_ALERT_TESTS_H
#define CH_TEST_SESSION_ALERT_TESTS_H

// Whether every key the session held is gone. rec_dir has padding, so its
// members compare one at a time.
static int session_keys_wiped(const ch_tls *t) {
    // At least as long as a rec_dir key and IV, and as a secret.
    static const uint8_t zero[SHA256_LEN] = {0};
    return t->keys == 0 && memcmp(t->rd.key, zero, sizeof t->rd.key) == 0 &&
           memcmp(t->rd.iv, zero, sizeof t->rd.iv) == 0 &&
           memcmp(t->wr.key, zero, sizeof t->wr.key) == 0 &&
           memcmp(t->wr.iv, zero, sizeof t->wr.iv) == 0 &&
           memcmp(t->rd_secret, zero, sizeof zero) == 0 &&
           memcmp(t->wr_secret, zero, sizeof zero) == 0;
}

// One protected alert of level and description after four bytes of data.
// The read that meets it fails the session and sends nothing, and the
// two reports survive ch_close, which has no key left to seal under.
static void read_peer_alert(uint8_t level, uint8_t description) {
    uint8_t secret[SHA256_LEN];
    ch_rand_bytes(secret, sizeof secret);
    rec_dir server;
    TEST_CPU_DIR(server);
    rec_dir_init(&server, secret);
    mock_io m = {0};
    static uint8_t rxbuf[1024];
    ch_tls t;
    mock_session(&t, &m, rxbuf, sizeof rxbuf, secret, NULL);
    const uint8_t alert[2] = {level, description};
    mock_push(&m, &server, REC_APPDATA, (const uint8_t *)"hola", 4);
    mock_push(&m, &server, REC_ALERT, alert, sizeof alert);

    uint8_t out[16];
    CHECK(ch_read(&t, out, sizeof out) == 4);
    CHECK(ch_alert_sent(&t) == 0 && ch_alert_received(&t) == 0);
    CHECK(ch_read(&t, out, sizeof out) == CH_EPROTO);
    CHECK(m.sends == 0);
    CHECK(t.state == CH_ST_FAILED && session_keys_wiped(&t));
    CHECK(ch_alert_received(&t) == description && ch_alert_sent(&t) == 0);
    CHECK(ch_read(&t, out, sizeof out) == CH_EPROTO);
    CHECK(ch_write(&t, out, 1) == CH_EPROTO);
    ch_close(&t);
    CHECK(m.sends == 0);
    CHECK(ch_alert_received(&t) == description && ch_alert_sent(&t) == 0);
}

// RFC 9846 §6 treats every description but close_notify and user_canceled
// as an error alert whatever the level byte says, and an unknown one too
// (rfc9846.txt:3779-3782).
static void test_peer_fatal_alert(void) {
    read_peer_alert(2, ALERT_HANDSHAKE_FAILURE);
    read_peer_alert(1, ALERT_BAD_CERTIFICATE);
    read_peer_alert(2, 255);
}

// A record of the alert type holds exactly one alert, 2 bytes (RFC 9846
// §5.1, rfc9846.txt:3475-3478). Two is the length read_peer_alert reads
// as an alert; one and three are the first on either side that are not.
// Each is a message that does not parse, so the read answers decode_error
// (rfc9846.txt:3785-3788) under the write key, once, and ch_alert_sent
// names it.
static void read_alert_of_length(size_t n) {
    uint8_t secret[SHA256_LEN];
    ch_rand_bytes(secret, sizeof secret);
    rec_dir server;
    TEST_CPU_DIR(server);
    rec_dir_init(&server, secret);
    mock_io m = {0};
    static uint8_t rxbuf[1024];
    ch_tls t;
    uint8_t wr_secret[SHA256_LEN];
    mock_session(&t, &m, rxbuf, sizeof rxbuf, secret, wr_secret);
    rec_dir reader;
    TEST_CPU_DIR(reader);
    rec_dir_init(&reader, wr_secret);
    const uint8_t body[3] = {2, ALERT_HANDSHAKE_FAILURE, 0};
    mock_push(&m, &server, REC_ALERT, body, n);

    uint8_t out[16];
    CHECK(ch_read(&t, out, sizeof out) == CH_EPROTO);
    CHECK(t.state == CH_ST_FAILED && session_keys_wiped(&t));
    CHECK(ch_alert_sent(&t) == ALERT_DECODE_ERROR && ch_alert_received(&t) == 0);
    uint8_t pt[16];
    size_t pt_len = 0;
    uint8_t type = 0;
    size_t at = mock_pop_client_record(&m, 0, &reader, pt, sizeof pt, &pt_len, &type);
    CHECK(type == REC_ALERT && pt_len == 2 && pt[0] == 2 && pt[1] == ALERT_DECODE_ERROR);
    CHECK(at == m.tx_len && m.sends == 1);
}

static void test_alert_record_length(void) {
    read_alert_of_length(1);
    read_alert_of_length(3);
}

// An alert between two records of one split post-handshake message. RFC
// 9846 §5.1 lets no record of another type come between them, and the
// peer's fatal alert there is still the peer's fatal alert: the read
// sends nothing. A malformed one is decode_error there too.
static void read_alert_inside_message(const uint8_t *alert, size_t n) {
    uint8_t secret[SHA256_LEN];
    ch_rand_bytes(secret, sizeof secret);
    rec_dir server;
    TEST_CPU_DIR(server);
    rec_dir_init(&server, secret);
    mock_io m = {0};
    static uint8_t rxbuf[1024];
    ch_tls t;
    mock_session(&t, &m, rxbuf, sizeof rxbuf, secret, NULL);
    // The first ten bytes of a 100-byte NewSessionTicket: the message is
    // incomplete, so the read asks for the next record.
    uint8_t part[10] = {HS_NEW_SESSION_TICKET, 0, 0, 96};
    mock_push(&m, &server, REC_HANDSHAKE, part, sizeof part);
    mock_push(&m, &server, REC_ALERT, alert, n);

    uint8_t out[16];
    CHECK(ch_read(&t, out, sizeof out) == CH_EPROTO);
    CHECK(t.state == CH_ST_FAILED && session_keys_wiped(&t));
    if (n == 2) {
        CHECK(ch_alert_received(&t) == alert[1] && ch_alert_sent(&t) == 0);
        CHECK(m.sends == 0);
    } else {
        CHECK(ch_alert_received(&t) == 0 && ch_alert_sent(&t) == ALERT_DECODE_ERROR);
        CHECK(m.sends == 1 && m.tx_len == CH_ALERT_RECORD_LEN);
    }
}

static void test_alert_inside_message(void) {
    const uint8_t fatal[3] = {2, ALERT_DECRYPT_ERROR, 0};
    read_alert_inside_message(fatal, 2);
    read_alert_inside_message(fatal, 3);
}

// tlsi_fail writes ch_alert_sent on every failure a live session meets,
// here a protected record whose inner type is change_cipher_spec, which
// RFC 9846 §5 refuses with unexpected_message (rfc9846.txt:3433-3435),
// and a send that fails. A failed send is this side's failure and not the
// peer's, so both ch_write and the reply ch_read owes a KeyUpdate answer
// it with internal_error (RFC 9846 §6.2, rfc9846.txt:3979-3981).
static void test_failure_alert_recorded(void) {
    uint8_t secret[SHA256_LEN];
    ch_rand_bytes(secret, sizeof secret);
    rec_dir server;
    TEST_CPU_DIR(server);
    rec_dir_init(&server, secret);
    mock_io m = {0};
    static uint8_t rxbuf[1024];
    ch_tls t;
    uint8_t wr_secret[SHA256_LEN];
    mock_session(&t, &m, rxbuf, sizeof rxbuf, secret, wr_secret);
    rec_dir reader;
    TEST_CPU_DIR(reader);
    rec_dir_init(&reader, wr_secret);
    const uint8_t ccs[1] = {1};
    mock_push(&m, &server, REC_CCS, ccs, sizeof ccs);
    uint8_t out[16];
    CHECK(ch_read(&t, out, sizeof out) == CH_EPROTO);
    CHECK(ch_alert_sent(&t) == ALERT_UNEXPECTED_MESSAGE && ch_alert_received(&t) == 0);
    uint8_t pt[16];
    size_t pt_len = 0;
    uint8_t type = 0;
    (void)mock_pop_client_record(&m, 0, &reader, pt, sizeof pt, &pt_len, &type);
    CHECK(type == REC_ALERT && pt_len == 2 && pt[1] == ALERT_UNEXPECTED_MESSAGE);

    mock_io m2 = {0};
    ch_tls t2;
    mock_session(&t2, &m2, rxbuf, sizeof rxbuf, secret, NULL);
    m2.fail_after = 1;
    CHECK(ch_write(&t2, (const uint8_t *)"x", 1) == CH_EIO);
    CHECK(ch_alert_sent(&t2) == ALERT_INTERNAL_ERROR && ch_alert_received(&t2) == 0);

    static const uint8_t update_requested[5] = {HS_KEY_UPDATE, 0, 0, 1, 1};
    mock_io m3 = {0};
    ch_tls t3;
    rec_dir peer;
    TEST_CPU_DIR(peer);
    rec_dir_init(&peer, secret);
    mock_session(&t3, &m3, rxbuf, sizeof rxbuf, secret, NULL);
    mock_push(&m3, &peer, REC_HANDSHAKE, update_requested, sizeof update_requested);
    m3.fail_after = 1;
    CHECK(ch_read(&t3, out, sizeof out) == CH_EIO);
    CHECK(ch_alert_sent(&t3) == ALERT_INTERNAL_ERROR && ch_alert_received(&t3) == 0);
}

#endif
