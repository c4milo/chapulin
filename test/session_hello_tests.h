// What ch_connect does with a first ClientHello it cannot stage or cannot
// send. Included by session_tests.h after the mock helpers exist; not a
// standalone translation unit.
#ifndef CH_SESSION_HELLO_TESTS_H
#define CH_SESSION_HELLO_TESTS_H

// A first ClientHello the staging array cannot hold. CH_HELLO_MAX is
// sized for a PSK identity of at most CH_TICKET_ID_MAX bytes
// (test_hello_staging_boundary in session_cfg_tests.h), and the raw and
// ca configuration checks put no bound on an external one. An identity as
// long as the whole array fits in no hello. ch_connect builds the hello
// before it sends a byte, so it refuses the connection on entry, as
// ch_record_init and ch_quic_init do: CH_EINVAL, no send, no alert
// recorded and a dead session. It returned CH_ECAP after an
// internal_error alert in the clear.
static void test_connect_refuses_unbuildable_hello(void) {
    static uint8_t rxbuf[CH_MIN_RXBUF];
    static uint8_t identity[CH_TX_STAGE];
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
    cfg.psk_id_len = sizeof identity;
    static ch_tls t;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
    CHECK(m.sends == 0 && ch_alert_sent(&t) == 0);
    CHECK(t.state == CH_ST_FAILED && t.keys == 0);
    // The same configuration with a CH_TICKET_ID_MAX identity sends its
    // hello and waits on the peer, which this mock never answers.
    cfg.psk_id_len = CH_TICKET_ID_MAX;
    CHECK(ch_connect(&t, &cfg) == CH_EIO);
    CHECK(m.sends == 2); // the hello, then the alert of the failed read
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
