// The session test/webpki_resume_test.c runs, and the one call that
// runs its handshake, over whichever transport the binary was built
// for. Included after the mock server.
#ifndef CH_TEST_WEBPKI_RESUME_SESSION_H
#define CH_TEST_WEBPKI_RESUME_SESSION_H

#ifdef CH_TRANSPORT_RECORD
static ch_record session;

static ch_tls *session_tls(void) {
    return &session.t;
}

// Hands every staged record to the mock, as a caller hands them to its
// socket. The first one is the ClientHello, which the mock answers.
static void drain_out(mock_server *s) {
    uint8_t out[REC_HDR + CH_TX_STAGE];
    size_t out_len = 0;
    while (ch_record_out(&session, out, sizeof out, &out_len) == CH_OK && out_len > 0) {
        (void)mock_send(s, out, out_len);
    }
}

// ch_record_init, then the mock's answer through ch_record_in, then the
// client's Finished out. Returns CH_OK once connected, or the first
// error.
static int connect_session(const ch_cfg *cfg) {
    int rc = ch_record_init(&session, cfg);
    if (rc != CH_OK) {
        return rc;
    }
    mock_server *s = cfg->io;
    drain_out(s);
    size_t off = 0;
    while (off < s->queue_len) {
        size_t consumed = 0;
        rc = ch_record_in(&session, s->queue + off, s->queue_len - off, &consumed);
        if (rc != CH_OK) {
            return rc;
        }
        if (consumed == 0) {
            break;
        }
        off += consumed;
    }
    s->queue_off = off;
    drain_out(s);
    return ch_record_state(&session) == CH_ST_CONNECTED ? CH_OK : CH_EPROTO;
}
#else
static ch_tls session;

static ch_tls *session_tls(void) {
    return &session;
}

static int connect_session(const ch_cfg *cfg) {
    return ch_connect(&session, cfg);
}
#endif

#endif
