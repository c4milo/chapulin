// ch_connect's PSK identity bound, which keeps every first ClientHello
// inside ch_tls.tx, and what it does with a hello whose send fails.
// Included by session_tests.h after the mock helpers exist; not a
// standalone translation unit.
#ifndef CH_SESSION_HELLO_TESTS_H
#define CH_SESSION_HELLO_TESTS_H

// The identity bound at its boundaries. An identity of CH_TICKET_ID_MAX
// bytes is taken: the hello goes out and the handshake waits on the peer,
// which this mock never answers. One byte more is refused on entry,
// CH_EINVAL with no send, no alert recorded and a dead session, and so is
// an empty identity, which RFC 9846 §4.3.11 does not allow
// (rfc9846.txt:2468-2471). CH_HELLO_MAX holds the longest hello the bound
// admits (test_hello_staging_boundary in session_cfg_tests.h), so no
// configuration reaches ch_handshake's branch for a hello that does not
// fit, and no test does.
static void test_connect_psk_identity_bounds(void) {
    static uint8_t rxbuf[CH_MIN_RXBUF];
    static uint8_t identity[CH_TICKET_ID_MAX + 1];
    uint8_t psk[32] = {1};
    mock_io m = {0};
    ch_cfg cfg = {0};
    cfg.buf = rxbuf;
    cfg.buf_len = sizeof rxbuf;
    cfg.send = mock_send;
    cfg.recv = mock_recv;
    cfg.io = &m;
    cfg.psk = psk;
    cfg.psk_len = sizeof psk;
    cfg.psk_id = identity;
    static ch_tls t;
    cfg.psk_id_len = CH_TICKET_ID_MAX;
    CHECK(ch_connect(&t, &cfg) == CH_EIO);
    CHECK(m.sends == 2); // the hello, then the alert of the failed read
    m.sends = 0;
    cfg.psk_id_len = CH_TICKET_ID_MAX + 1;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
    CHECK(m.sends == 0 && ch_alert_sent(&t) == 0);
    CHECK(t.state == CH_ST_FAILED && t.keys == 0);
    cfg.psk_id_len = 0;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
    CHECK(m.sends == 0 && ch_alert_sent(&t) == 0);
}

// A first ClientHello whose send fails. The failure is this side's
// transport and not the peer's, so the handshake records internal_error
// (RFC 9846 §6.2, rfc9846.txt:3979-3981), the alert ch_write names for a
// failed send, and then tries to send it as it does every alert.
static void test_connect_hello_send_fails(void) {
    static uint8_t rxbuf[CH_MIN_RXBUF];
    uint8_t psk[32] = {1};
    mock_io m = {0};
    m.fail_after = 1;
    ch_cfg cfg = {0};
    cfg.buf = rxbuf;
    cfg.buf_len = sizeof rxbuf;
    cfg.send = mock_send;
    cfg.recv = mock_recv;
    cfg.io = &m;
    cfg.psk = psk;
    cfg.psk_len = sizeof psk;
    cfg.psk_id = (const uint8_t *)"d";
    cfg.psk_id_len = 1;
    static ch_tls t;
    CHECK(ch_connect(&t, &cfg) == CH_EIO);
    CHECK(ch_alert_sent(&t) == ALERT_INTERNAL_ERROR && ch_alert_received(&t) == 0);
    CHECK(m.sends == 2 && t.state == CH_ST_FAILED);
}

#endif
