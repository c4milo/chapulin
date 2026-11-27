// The session test/webpki_resume_test.c runs, and the one call that
// runs its handshake, over whichever transport the binary was built
// for. Included after the mock server.
#ifndef CH_TEST_WEBPKI_RESUME_SESSION_H
#define CH_TEST_WEBPKI_RESUME_SESSION_H

#include "test_read.h"

#ifdef CH_TRANSPORT_TCP_NONBLOCKING
static ch_tcp_priv session;

static ch_tls_priv *session_tls(void) {
    return &session.t;
}

// Hands every staged record to the mock, as a caller hands them to its
// socket. The first one is the ClientHello, which the mock answers.
static void drain_out(mock_server *s) {
    uint8_t out[REC_HDR + CH_TX_STAGE];
    size_t out_len = 0;
    while (ch_tcp_out(tcp_public(&session), out, sizeof out, &out_len) == CH_OK && out_len > 0) {
        (void)mock_send(s, out, out_len);
    }
}

// ch_tcp_init, then the mock's answer through ch_tcp_in, handing
// the mock what the client staged after each call: a retry hello after a
// HelloRetryRequest, which the mock answers onto the same queue, and the
// client's Finished at the end. A failure's alert record goes to the mock
// the same way, as cfg.send carries the tcp-blocking client's. The records
// after the handshake are test_read's, which reads them through the
// session's recv, mock_recv, and sends an alert through its send,
// mock_send (test/test_read.h). The test sets mock_send on the session's
// copy of cfg after init and mock_recv once connected, and the
// configuration sets neither. Returns CH_OK once connected, or the first
// error.
static int connect_session(const ch_cfg *cfg) {
    test_read_reset();
    int rc = ch_tcp_init(tcp_public(&session), cfg);
    if (rc != CH_OK) {
        return rc;
    }
    session.t.cfg.send = mock_send;
    mock_server *s = cfg->io;
    drain_out(s);
    size_t off = 0;
    while (off < s->queue_len) {
        size_t consumed = 0;
        rc = ch_tcp_in(tcp_public(&session), s->queue + off, s->queue_len - off, &consumed);
        if (rc != CH_OK) {
            drain_out(s);
            return rc;
        }
        if (consumed == 0) {
            break;
        }
        off += consumed;
        drain_out(s);
    }
    s->queue_off = off;
    session.t.cfg.recv = mock_recv;
    return ch_tcp_state(tcp_public(&session)) == CH_ST_CONNECTED ? CH_OK : CH_EPROTO;
}
#else
static ch_tls_priv session;

static ch_tls_priv *session_tls(void) {
    return &session;
}

static int connect_session(const ch_cfg *cfg) {
    return ch_connect(tls_public(&session), cfg);
}
#endif

// The alert the client sent when its handshake failed, which the mock
// read off the wire: in the clear, or sealed under the client's handshake
// write key.
static uint8_t session_alert(const mock_server *s) {
    return s->alert;
}

#endif
