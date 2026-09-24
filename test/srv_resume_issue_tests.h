// srv_resume.c's other half: a ticket on a retried hello, the binder
// hash srv_read_client_hello takes, and the NewSessionTicket a connection
// ends with. It continues test/srv_resume_tests.h, whose tickets and
// helpers it reads, and includes it for the reason that file gives; the two
// are one case list split because CLAUDE.md caps a hand-written file at 500
// lines.
#ifndef CH_SRV_RESUME_ISSUE_TESTS_H
#define CH_SRV_RESUME_ISSUE_TESTS_H

#include "srv_resume_tests.h"

// A driver that zeroes its selection before the second hello, as
// srv_rec.c and srv_quic.c do, gets the first hello's scheme back, because
// srv_check_retry_hello reads nothing from sel. It once left sigalg 0 there,
// and every retried handshake on those two transports failed at the
// Certificate.
static void test_retry_zeroed_selection(void) {
    selection sel;
    retry_round(&sel);
    CHECK(sel.sigalg != 0);
    // cookie_echo is file-scope, so flight_hello never points at this frame.
    size_t cookie_len = hs.cookie_len;
    memcpy(cookie_echo, hs.cookie, cookie_len);
    offer_everything();
    flight_hello.cookie = cookie_echo;
    flight_hello.cookie_len = cookie_len;
    selection zeroed;
    memset(&zeroed, 0, sizeof zeroed);
    CHECK(srv_check_retry_hello(&hs, &flight_hello, &zeroed) == CH_OK);
    CHECK(zeroed.sigalg == sel.sigalg && zeroed.psk_selected == 0);
}

// A ticket on the hello that owes a retry is not judged: srv_select
// answers with need_retry and selects nothing, so no binder over the first
// hello is checked. The second hello carries it again, and
// srv_check_retry_hello resumes it there under the binder over the
// retried transcript.
static void test_resume_after_retry(void) {
    selection sel;
    uint8_t ticket[SRV_TICKET_LEN];
    uint8_t binder[SHA256_LEN];

    retry_round(&sel);
    CHECK(sel.psk_selected == 0);
    for (size_t i = 0; i < SHA256_LEN; i++) {
        resume_psk[i] = (uint8_t)(0x80 + i);
        resume_hash[i] = (uint8_t)(0x30 + i);
    }
    sess.cfg.srv.ticket_key = resume_key;
    sess.cfg.srv.now_seconds = RESUME_AUTH;
    resume_ticket(ticket, resume_key, RESUME_AUTH, CH_ALPN_NONE);
    resume_binder(binder);
    // cookie_echo is file-scope, so flight_hello never points at this frame.
    size_t cookie_len = hs.cookie_len;
    memcpy(cookie_echo, hs.cookie, cookie_len);
    resume_offer offer = {ticket, SRV_TICKET_LEN, binder, sizeof binder};
    offer_tickets(&offer, 1);
    flight_hello.cookie = cookie_echo;
    flight_hello.cookie_len = cookie_len;
    selection second;
    memset(&second, 0, sizeof second);
    CHECK(srv_check_retry_hello(&hs, &flight_hello, &second) == CH_OK && resumed(&second));

    // A binder over any other transcript fails there as it fails on a
    // first hello.
    flight_hello.binder_hash[31] ^= 0x80;
    CHECK(srv_check_retry_hello(&hs, &flight_hello, &second) == CH_EAUTH);
    CHECK(hs.alert == ALERT_DECRYPT_ERROR);
}

// srv_read_client_hello's binder_hash: the transcript so far and the
// message up to its binders, and nothing written for a hello with no PSK.
static void test_resume_binder_hash(void) {
    static const uint8_t zero[SHA256_LEN] = {0};
    flight_reset();
    srv_begin(&hs);
    offer_everything();
    parse_result.truncated_len = 20;
    feed_handshake(HS_CLIENT_HELLO, FLIGHT_HELLO_BODY);
    CHECK(srv_read_client_hello(&hs, &flight_hello) == CH_OK);
    uint8_t want[SHA256_LEN];
    sha256_of(feed + REC_HDR, 4 + 20, want);
    CHECK(memcmp(flight_hello.binder_hash, want, sizeof want) == 0);

    flight_reset();
    srv_begin(&hs);
    offer_everything();
    feed_handshake(HS_CLIENT_HELLO, FLIGHT_HELLO_BODY);
    CHECK(srv_read_client_hello(&hs, &flight_hello) == CH_OK);
    CHECK(memcmp(flight_hello.binder_hash, zero, sizeof zero) == 0);
}

// Runs a whole flight to the verified client Finished, ready for the
// ticket, with the server clock at now.
static void resume_connected(uint64_t now, rec_dir *client_rd) {
    selection sel;
    rec_dir rd;
    auth_flight(&sel, &rd);
    sess.cfg.srv.ticket_key = resume_key;
    sess.cfg.srv.now_seconds = now;
    CHECK(srv_send_finished(&hs) == CH_OK);
    feed_client_finished(1);
    CHECK(srv_read_client_finished(&hs) == CH_OK);
    srv_complete(&hs);
    rec_dir_init(client_rd, sess.wr_secret);
    wire_len = 0;
}

// Opens the one NewSessionTicket record the server wrote and reads the
// ticket out of it. Returns the message length, or 0 when none was written.
static size_t read_issued_ticket(rec_dir *client_rd, uint32_t *lifetime, uint8_t *nonce,
                                 srv_ticket_contents *c) {
    if (wire_len == 0) {
        return 0;
    }
    uint8_t msg[256];
    size_t n = 0;
    uint8_t inner = 0;
    CHECK(rec_open(client_rd, wire, wire_len, msg, sizeof msg, &n, &inner) == 0);
    CHECK(inner == REC_HANDSHAKE && msg[0] == HS_NEW_SESSION_TICKET);
    rbuf r;
    rb_init(&r, msg + 4, n - 4);
    uint32_t hi = rb_u24(&r);
    *lifetime = (hi << 8) | rb_u8(&r);
    (void)rb_u24(&r);
    (void)rb_u8(&r);
    CHECK(rb_u8(&r) == SRV_TICKET_NONCE_LEN);
    memcpy(nonce, rb_bytes(&r, SRV_TICKET_NONCE_LEN), SRV_TICKET_NONCE_LEN);
    CHECK(rb_u16(&r) == SRV_TICKET_LEN);
    const uint8_t *ticket = rb_bytes(&r, SRV_TICKET_LEN);
    CHECK(rb_u16(&r) == 0); // no extension, so no early_data
    CHECK(!r.err && rb_left(&r) == 0);
    CHECK(srv_ticket_open(resume_key, ticket, SRV_TICKET_LEN, c) == CH_OK);
    return n;
}

static void test_resume_issue(void) {
    rec_dir client_rd;
    uint32_t lifetime = 0;
    uint8_t nonce[SRV_TICKET_NONCE_LEN] = {0};
    srv_ticket_contents c;
    memset(&c, 0, sizeof c);

    // After a full handshake: the whole lifetime, this instant, this suite,
    // and the PSK RFC 9846 §4.7.1 derives from the resumption secret over
    // the transcript through the client Finished.
    resume_connected(RESUME_AUTH, &client_rd);
    uint8_t hash[SHA256_LEN];
    (void)hsr_transcript_hash(&hs, hash);
    uint8_t res_master[SHA256_LEN];
    ks_res_master(hs.master, hash, res_master);
    CHECK(srv_send_new_session_ticket(&hs) == CH_OK);
    CHECK(records_written() == 1);
    CHECK(read_issued_ticket(&client_rd, &lifetime, nonce, &c) > 0);
    CHECK(lifetime == SRV_TICKET_LIFETIME && c.auth_seconds == RESUME_AUTH);
    CHECK(c.suite == SUITE_CHACHA20_POLY1305_SHA256 && c.alpn_len == 0);
    uint8_t psk[SHA256_LEN];
    ks_res_psk(res_master, nonce, sizeof nonce, psk);
    CHECK(memcmp(c.psk, psk, sizeof psk) == 0);

    // After a resumed one: the instant the resumed ticket carried, and what
    // is left of the lifetime.
    resume_connected(RESUME_AUTH + 10, &client_rd);
    sess.psk_selected = 1;
    hs.ticket_auth_seconds = RESUME_AUTH;
    CHECK(srv_send_new_session_ticket(&hs) == CH_OK);
    CHECK(read_issued_ticket(&client_rd, &lifetime, nonce, &c) > 0);
    CHECK(lifetime == SRV_TICKET_LIFETIME - 10 && c.auth_seconds == RESUME_AUTH);

    // A resumed chain at the end of its lifetime has nothing left to give,
    // and one second before the end it gives one second.
    resume_connected((uint64_t)RESUME_AUTH + SRV_TICKET_LIFETIME, &client_rd);
    sess.psk_selected = 1;
    hs.ticket_auth_seconds = RESUME_AUTH;
    CHECK(srv_send_new_session_ticket(&hs) == CH_OK && wire_len == 0);
    resume_connected((uint64_t)RESUME_AUTH + SRV_TICKET_LIFETIME - 1, &client_rd);
    sess.psk_selected = 1;
    hs.ticket_auth_seconds = RESUME_AUTH;
    CHECK(srv_send_new_session_ticket(&hs) == CH_OK);
    CHECK(read_issued_ticket(&client_rd, &lifetime, nonce, &c) > 0 && lifetime == 1);

    // The ALPN protocol the connection selected goes into the ticket.
    resume_connected(RESUME_AUTH, &client_rd);
    sess.cfg.alpn_protocols = flight_alpn;
    sess.cfg.alpn_count = 2;
    sess.alpn_selected = 1;
    CHECK(srv_send_new_session_ticket(&hs) == CH_OK);
    CHECK(read_issued_ticket(&client_rd, &lifetime, nonce, &c) > 0);
    CHECK(c.alpn_len == sizeof alpn_http11 && memcmp(c.alpn, alpn_http11, c.alpn_len) == 0);

    // No clock or no key: no ticket, and no error.
    resume_connected(RESUME_AUTH, &client_rd);
    sess.cfg.srv.now_seconds = 0;
    CHECK(srv_send_new_session_ticket(&hs) == CH_OK && wire_len == 0);
    resume_connected(RESUME_AUTH, &client_rd);
    sess.cfg.srv.ticket_key = NULL;
    CHECK(srv_send_new_session_ticket(&hs) == CH_OK && wire_len == 0);

    // A transport that refuses the write reports CH_EIO.
    resume_connected(RESUME_AUTH, &client_rd);
    send_rc = -1;
    CHECK(srv_send_new_session_ticket(&hs) == CH_EIO);
}

#endif
