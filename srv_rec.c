// The tcp-nonblocking server driver: srv_flight.[ch]'s handlers run over TLS
// records, driven by a caller that owns the socket. srv_rec.h states the
// contract; this file is srv_quic.c's mirror on the transport that keeps
// its records, and srv_handshake.c's on a caller that will not block.
//
// It holds no protocol rule of its own. The handlers decide what a
// message says, srv_out.c decides how its bytes leave, and this file
// decides only which handler runs next. It installs no keys either:
// every rec_dir_init a server makes already sits inside the handler that
// derived the secret it takes (srv_flight.c:308, 425 and 464), because
// the blocking driver needs them there too.
//
// One step per message the server waits for, and three is all there are:
// the ClientHello, the second ClientHello after a HelloRetryRequest, and
// the client Finished. Every send sits inside the step that read the
// message it answers, because a server pushes its flight rather than
// staging it for a caller to collect, so no send needs a step of its own
// and no flight suspends half-written.
#include "srv_rec.h"

#if defined(CH_ROLE_SERVER) && defined(CH_TRANSPORT_TCP_NONBLOCKING)

#include "ch_assert.h"

#include <string.h>

#include "ct.h"
#include "handshake_record.h"
#include "rec_frame.h"
#include "record.h"
#include "srv_flight.h"
#include "srv_resume.h"

// Everything the server owes once a hello is accepted, whether it was the
// first or the one that answered a HelloRetryRequest. Every record of it
// leaves through cfg.srv.on_record_out before this call returns.
static int server_flight(ch_record *r, const client_hello *ch, const selection *sel) {
    handshake_state *h = &r->hs;
    int rc = srv_send_server_hello(h, ch, sel);
    if (rc != CH_OK) {
        return rc;
    }
    rc = srv_send_compat_ccs(h, ch);
    if (rc != CH_OK) {
        return rc;
    }
    srv_store_selection(&r->t, ch, sel);
    rc = srv_derive_handshake_secrets(h, ch, sel);
    if (rc != CH_OK) {
        return rc;
    }
    rc = srv_send_encrypted_extensions(h, sel);
    if (rc != CH_OK) {
        return rc;
    }
    // A resumed handshake sends neither message: the ticket's PSK
    // authenticates this server.
    if (!sel->psk_selected) {
        rc = srv_send_certificate(h, sel);
        if (rc != CH_OK) {
            return rc;
        }
        rc = srv_send_certificate_verify(h, sel);
        if (rc != CH_OK) {
            return rc;
        }
    }
    rc = srv_send_finished(h);
    if (rc != CH_OK) {
        return rc;
    }
    r->step = SR_STEP_AWAIT_CLIENT_FINISHED;
    return CH_OK;
}

// The first ClientHello. A selection that asks for a retry sends one and
// waits; anything else answers with the flight.
//
// This is srv_send_hello_retry_request's one call site, so a second
// HelloRetryRequest is unreachable by call position rather than by a
// counter, exactly as srv_handshake.c arranges it.
static int step_client_hello(ch_record *r) {
    handshake_state *h = &r->hs;
    client_hello ch;
    selection sel;
    memset(&ch, 0, sizeof ch);
    memset(&sel, 0, sizeof sel);

    int rc = srv_read_client_hello(h, &ch);
    if (rc != CH_OK) {
        return rc;
    }
    rc = srv_select(h, &ch, &sel);
    if (rc != CH_OK) {
        return rc;
    }
    if (sel.need_retry) {
        rc = srv_send_hello_retry_request(h, &ch, &sel);
        if (rc != CH_OK) {
            return rc;
        }
        // The dummy change_cipher_spec sits after the HelloRetryRequest
        // when there was one and after the ServerHello when there was
        // not, which is why server_flight sends its own rather than this
        // arm falling into it. srv_flight.h states why that beats one
        // call site and a flag.
        rc = srv_send_compat_ccs(h, &ch);
        if (rc != CH_OK) {
            return rc;
        }
        r->step = SR_STEP_AWAIT_RETRY_HELLO;
        return CH_OK;
    }
    return server_flight(r, &ch, &sel);
}

// The second ClientHello. srv_check_retry_hello writes sel from the
// cookie and never sets need_retry, which is what keeps a second retry
// unreachable.
static int step_retry_hello(ch_record *r) {
    handshake_state *h = &r->hs;
    client_hello ch;
    selection sel;
    memset(&ch, 0, sizeof ch);
    memset(&sel, 0, sizeof sel);

    int rc = srv_read_client_hello(h, &ch);
    if (rc != CH_OK) {
        return rc;
    }
    rc = srv_check_retry_hello(h, &ch, &sel);
    if (rc != CH_OK) {
        return rc;
    }
    return server_flight(r, &ch, &sel);
}

// The client Finished, which is the last message of the handshake.
// srv_complete installs the application read key and raises the session
// to CH_ST_CONNECTED; the write key went in with srv_send_finished, one
// round trip earlier, because RFC 9846 section 4.5.3 lets a server write
// application data before it has read the client's Finished.
static int step_client_finished(ch_record *r) {
    int rc = srv_read_client_finished(&r->hs);
    if (rc != CH_OK) {
        return rc;
    }
    srv_complete(&r->hs);
    r->step = SR_STEP_COMPLETE;
    // The ticket leaves through on_record_out after the client Finished
    // verified (RFC 9846 §4.7.1), and before the wipe, because it needs
    // hs.master and the transcript.
    rc = srv_send_new_session_ticket(&r->hs);
    // INV-17: the handshake secrets die at CONNECTED. The wipe clears
    // hs.t with the rest, so this step writes the back pointer again.
    ct_wipe(&r->hs, sizeof r->hs);
    r->hs.t = &r->t;
    return rc;
}

// Nothing is legal here. The caller moves to ch_read the moment
// ch_record_state answers CH_ST_CONNECTED, and ch_read handles every
// post-handshake message this build accepts. Bytes fed to this driver
// after the handshake are a caller that did not move on.
static int step_complete(ch_record *r) {
    r->hs.alert = ALERT_UNEXPECTED_MESSAGE;
    return CH_EPROTO;
}

// Runs the one step r->step names, over the one whole handshake message
// hsr_peek_message has found. It is the only switch in the mode: it
// dispatches and does nothing else, so every path into a handler runs
// through a step number a step wrote.
static int advance(ch_record *r) {
    switch (r->step) {
    case SR_STEP_AWAIT_CLIENT_HELLO:
        return step_client_hello(r);
    case SR_STEP_AWAIT_RETRY_HELLO:
        return step_retry_hello(r);
    case SR_STEP_AWAIT_CLIENT_FINISHED:
        return step_client_finished(r);
    case SR_STEP_COMPLETE:
        return step_complete(r);
    default:
        // A step value no step wrote, which a one-byte corruption of
        // r->step produces. It kills the session instead of running a
        // handler or calling ch_assert_fail, because the step number is
        // data a fault can change and CH_ASSERT is for programmer error.
        r->hs.alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
}

// Runs every whole handshake message the fed plaintext now holds. It is
// rec.c's drive loop without the staging test, because a server pushes
// its flight instead of leaving it for the caller to collect.
static int drive(ch_record *r) {
    for (;;) {
        size_t raw_len = 0;
        int rc = hsr_peek_message(&r->hs, &raw_len, &r->hs.alert);
        if (rc == HSR_INCOMPLETE) {
            return CH_OK;
        }
        if (rc != CH_OK) {
            return rec_fail(r, rc);
        }
        rc = advance(r);
        if (rc != CH_OK) {
            return rec_fail(r, rc);
        }
    }
}

int ch_srv_record_init(ch_record *r, const ch_cfg *cfg) {
    // Neither pointer is checked, as ch_srv_accept does not check its
    // own: srv_rec.h makes "r and cfg are not NULL" a caller requirement.
    memset(r, 0, sizeof *r);
    r->t.cfg = *cfg;
    // srv_config_ok's transport_ok requires on_record_out, and srv_out.c's
    // emit calls it without a NULL test on the strength of that: a server
    // whose flight reaches nobody completes no handshake.
    if (!srv_config_ok(cfg)) {
        memset(r, 0, sizeof *r);
        r->t.state = CH_ST_FAILED;
        return CH_EINVAL;
    }
    r->hs.t = &r->t;
    // The description a failure carries when no handler chose a more
    // specific one, seeded the way srv_handshake seeds it.
    r->hs.alert = ALERT_DECODE_ERROR;
    // This server's own record_size_limit, sized to the caller's buffer,
    // which srv_send_encrypted_extensions puts in the
    // EncryptedExtensions. srv_store_selection lowers t->peer_limit to the
    // client's own limit once the hello has been read.
    size_t room = r->t.cfg.buf_len - REC_HDR - AEAD_TAG;
    r->hs.record_size_limit = room > 0x4001 ? 0x4001 : (uint16_t)room;
    r->t.peer_limit = CH_TX_PT;
    // 0 is the first protocol in ch_cfg.alpn_protocols, so the
    // no-selection value has to be written before the parser reports one.
    r->t.alpn_selected = CH_ALPN_NONE;
    // The key share this connection answers with, drawn before the first
    // byte arrives the way ch_srv_quic_init draws it.
    srv_begin(&r->hs);
    r->step = SR_STEP_AWAIT_CLIENT_HELLO;
    r->t.state = CH_ST_START;
    return CH_OK;
}

int ch_srv_record_in(ch_record *r, uint8_t *p, size_t n, size_t *consumed) {
    CH_ASSERT(r->t.state <= CH_ST_FAILED);
    r->hs.t = &r->t;
    *consumed = 0;
    if (rec_session_dead(r)) {
        return CH_EPROTO;
    }
    size_t off = 0;
    for (;;) {
        if (n - off < REC_HDR) {
            return CH_OK;
        }
        uint8_t *rec = p + off;
        size_t body_len = ((size_t)rec[3] << 8) | rec[4];
        if (body_len > 0x4000 + 256) {
            // RFC 9846 section 5.2 caps a record; anything larger names
            // no record this endpoint will ever read.
            r->hs.alert = ALERT_RECORD_OVERFLOW;
            return rec_fail(r, CH_EPROTO);
        }
        if (n - off < REC_HDR + body_len) {
            return CH_OK;
        }
        int rc = rec_take_record(r, rec, body_len, rec[0]);
        if (rc != CH_OK) {
            return rec_fail(r, rc);
        }
        off += REC_HDR + body_len;
        *consumed = off;
        rc = drive(r);
        if (rc != CH_OK) {
            return rc;
        }
        // The record that completed the handshake is the last one this
        // call takes: what follows it is the peer's application data or
        // alerts, and belongs to ch_read (srv_rec.h).
        if (r->step == SR_STEP_COMPLETE) {
            return CH_OK;
        }
    }
}

#endif // CH_ROLE_SERVER && CH_TRANSPORT_TCP_NONBLOCKING
