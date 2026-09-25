// The QUIC server driver: srv_flight.[ch]'s handlers run over CRYPTO
// frames. srv_quic.h states the contract; this file is the mirror of
// quic.c and quic_step.c on the other side of the connection, and of
// srv_handshake.c on the other transport.
//
// It holds no protocol rule of its own. The handlers decide what a
// message says, srv_out.c decides how its bytes leave, and this file
// decides only which handler runs next and which keys exist when it does.
//
// One step per message the server waits for, and three is all there are:
// the ClientHello, the second ClientHello after a HelloRetryRequest, and
// the client Finished. Every send sits inside the step that read the
// message it answers, because a server pushes its flight rather than
// staging it for a caller to collect, so no send needs a step of its own
// and no flight suspends half-written.
#include "srv_quic.h"

#if defined(CH_ROLE_SERVER) && defined(CH_TRANSPORT_QUIC_NONBLOCKING)

#include <string.h>

#include "ch_assert.h"
#include "ct.h"
#include "quic_fail.h"
#include "quic_keys.h"
#include "quic_retry.h"
#include "srv_flight.h"
#include "srv_resume.h"

// Reports one direction of one level as usable and records it. The bit
// and the callback move together, so the caller's view and
// q->levels_ready cannot disagree.
static void announce(ch_quic *q, uint8_t level, uint8_t direction) {
    q->levels_ready |= CH_QUIC_LEVEL_BIT(level, direction);
    q->t.cfg.on_level_ready(q->t.cfg.io, level, direction);
}

// The Handshake level's four keys, from the two handshake traffic secrets
// srv_derive_handshake_secrets wrote. A server reads under the client's
// secret and writes under its own, the mirror of quic_step.c:33-36, and
// both directions exist at once because one derivation wrote both.
static void install_handshake_keys(ch_quic *q) {
    QUIC_KEYS_INIT_SUITE(&q->handshake_rx, q->hs.c_hs, q->t.suite);
    QUIC_HP_KEY_INIT_SUITE(&q->handshake_hp_rx, q->hs.c_hs, q->t.suite);
    QUIC_KEYS_INIT_SUITE(&q->handshake_tx, q->hs.s_hs, q->t.suite);
    QUIC_HP_KEY_INIT_SUITE(&q->handshake_hp_tx, q->hs.s_hs, q->t.suite);
    announce(q, CH_LEVEL_HANDSHAKE, CH_KEY_READ);
    announce(q, CH_LEVEL_HANDSHAKE, CH_KEY_WRITE);
}

// The 1-RTT keys. Both sets are written here, because srv_send_finished's
// ks_master wrote both secrets, but only the write direction is announced:
// RFC 9846 section 4.5.3 has the server's Finished authorize its own
// application data while the client's is still outstanding, so a server
// may write 1-RTT before it may read one. The read direction is announced
// when that Finished verifies.
//
// t.rd_secret afterwards names app_rx[CH_QUIC_KEY_NEXT], not the current
// set, which is the invariant session.h states and ch_quic_key_update
// depends on.
static void install_application_keys(ch_quic *q) {
    QUIC_KEYS_INIT_SUITE(&q->app_tx, q->t.wr_secret, q->t.suite);
    QUIC_HP_KEY_INIT_SUITE(&q->app_hp_tx, q->t.wr_secret, q->t.suite);
    QUIC_KEYS_INIT_SUITE(&q->app_rx[CH_QUIC_KEY_CURRENT], q->t.rd_secret, q->t.suite);
    QUIC_HP_KEY_INIT_SUITE(&q->app_hp_rx, q->t.rd_secret, q->t.suite);
    // The next set starts as the current one, so the update derives it
    // under the suite that set records.
    q->app_rx[CH_QUIC_KEY_NEXT] = q->app_rx[CH_QUIC_KEY_CURRENT];
    quic_keys_update(q->t.rd_secret, &q->app_rx[CH_QUIC_KEY_NEXT]);
    announce(q, CH_LEVEL_APPLICATION, CH_KEY_WRITE);
}

// What the session keeps past the message that decided it, the copy
// srv_handshake.c makes at the same point. This driver is the only scope
// holding the selection, the parsed hello and the session at once.
//
// No record_size_limit is copied: RFC 9001 section 4.1.3 removes the
// record layer it sizes, srv_parser.c refuses the extension from a QUIC
// client, and a QUIC build declares no ch_tls.peer_limit to hold it.
static void store_selection(ch_tls *t, const client_hello *ch, const selection *sel) {
    t->suite = sel->suite;
    t->hash_len = sel->hash_len;
    t->group = sel->group;
    t->sigalg = sel->sigalg;
    t->psk_selected = sel->psk_selected;
    t->alpn_selected = ch->alpn_selected;
}

// RFC 9001 section 8.2 requires the quic_transport_parameters extension in
// every ClientHello and makes its absence an error of type 0x016d, which
// is a fatal missing_extension alert (rfc9001.txt:1929-1936). The body is
// handed to the caller unread; it points into cfg.buf, so the callback
// sees it before the next message overwrites that buffer.
static int take_transport_params(ch_quic *q, const client_hello *ch) {
    if (ch->transport_params == NULL) {
        q->hs.alert = ALERT_MISSING_EXTENSION;
        return CH_EPROTO;
    }
    if (q->t.cfg.on_transport_params != NULL) {
        q->t.cfg.on_transport_params(q->t.cfg.io, ch->transport_params, ch->transport_params_len);
    }
    return CH_OK;
}

// Everything the server owes once a hello is accepted, whether it was the
// first or the one that answered a HelloRetryRequest. The ServerHello
// goes out at the Initial level and the rest at the Handshake level,
// which is why h->level is written twice.
static int server_flight(ch_quic *q, const client_hello *ch, const selection *sel) {
    handshake_state *h = &q->hs;
    int rc = take_transport_params(q, ch);
    if (rc != CH_OK) {
        return rc;
    }
    h->level = CH_LEVEL_INITIAL;
    rc = srv_send_server_hello(h, ch, sel);
    if (rc != CH_OK) {
        return rc;
    }
    store_selection(&q->t, ch, sel);
    rc = srv_derive_handshake_secrets(h, ch, sel);
    if (rc != CH_OK) {
        return rc;
    }
    install_handshake_keys(q);
    h->level = CH_LEVEL_HANDSHAKE;
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
    install_application_keys(q);
    q->rx_level = CH_LEVEL_HANDSHAKE;
    q->step = SQ_STEP_AWAIT_CLIENT_FINISHED;
    return CH_OK;
}

// The first ClientHello. A selection that asks for a retry sends one and
// waits; anything else answers with the flight.
//
// This is srv_send_hello_retry_request's one call site, so a second
// HelloRetryRequest is unreachable by call position rather than by a
// counter, exactly as srv_handshake.c arranges it.
static int step_client_hello(ch_quic *q) {
    handshake_state *h = &q->hs;
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
        h->level = CH_LEVEL_INITIAL;
        rc = srv_send_hello_retry_request(h, &ch, &sel);
        if (rc != CH_OK) {
            return rc;
        }
        q->step = SQ_STEP_AWAIT_RETRY_HELLO;
        return CH_OK;
    }
    return server_flight(q, &ch, &sel);
}

// The second ClientHello. srv_check_retry_hello writes sel from the
// cookie and never sets need_retry, which is what keeps a second retry
// unreachable.
static int step_retry_hello(ch_quic *q) {
    handshake_state *h = &q->hs;
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
    return server_flight(q, &ch, &sel);
}

// The client Finished, which is the last message of the handshake. The
// read direction of the application level becomes usable here and not
// before, because this is what authenticates the client's half.
static int step_client_finished(ch_quic *q) {
    int rc = srv_read_client_finished(&q->hs);
    if (rc != CH_OK) {
        return rc;
    }
    // Bytes after the Finished in cfg.buf are data at the level this
    // step leaves. srv_complete empties cfg.buf, so drive's check would
    // never see them, and they are refused here instead: before the
    // application read key is announced and before the ticket goes out.
    if (q->t.pt_off != q->t.pt_len) {
        return quic_refuse_unread(q);
    }
    srv_complete(&q->hs);
    announce(q, CH_LEVEL_APPLICATION, CH_KEY_READ);
    q->rx_level = CH_LEVEL_APPLICATION;
    q->step = SQ_STEP_COMPLETE;
    // The ticket goes out in 1-RTT CRYPTO frames (RFC 9001 section 4.5),
    // after the client Finished verified and before the wipe, because it
    // needs hs.master and the transcript.
    q->hs.level = CH_LEVEL_APPLICATION;
    rc = srv_send_new_session_ticket(&q->hs);
    // INV-17: the handshake secrets die at CONNECTED, one round trip
    // earlier than the tcp-blocking driver wipes its frame, because this one owns
    // the state the other keeps on a stack frame that is about to return.
    ct_wipe(&q->hs, sizeof q->hs);
    q->hs.t = &q->t;
    return rc;
}

// Runs the one step q->step names, over the one whole handshake message
// that already sits in cfg.buf. The only switch in the mode: it dispatches
// and does nothing else, so every path into a handler runs through a step
// number a step wrote.
static int advance(ch_quic *q) {
    switch (q->step) {
    case SQ_STEP_AWAIT_CLIENT_HELLO:
        return step_client_hello(q);
    case SQ_STEP_AWAIT_RETRY_HELLO:
        return step_retry_hello(q);
    case SQ_STEP_AWAIT_CLIENT_FINISHED:
        return step_client_finished(q);
    default:
        // SQ_STEP_COMPLETE. RFC 9001 section 4.1.3 makes CRYPTO data
        // after the handshake a connection error unless it is a message
        // this stack handles, and a server here handles none.
        q->hs.alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
}

static int session_dead(const ch_quic *q) {
    return q->t.state == CH_ST_CLOSED || q->t.state == CH_ST_FAILED;
}

// The input loop, the shape quic.c's drive has. It copies what fits, asks
// whether a whole message is present, runs one step if it is, and returns
// when it is not.
//
// It terminates for the reason quic.c states: the copy compacts first, so
// input bytes left over mean a full buffer, a full buffer holds at least
// CH_MIN_RXBUF bytes, and hsr_peek_message therefore always reads its
// 4-byte header rather than answering HSR_INCOMPLETE. Each iteration then
// either returns or runs a step, and a step consumes a whole message.
static int drive(ch_quic *q, const uint8_t *p, size_t n) {
    size_t off = 0;
    for (;;) {
        off += hsr_feed(&q->hs, p + off, n - off);
        size_t raw_len = 0;
        int rc = hsr_peek_message(&q->hs, &raw_len, &q->hs.alert);
        if (rc == HSR_INCOMPLETE) {
            return CH_OK;
        }
        if (rc != CH_OK) {
            return quic_fail(q, rc);
        }
        uint8_t was = q->rx_level;
        rc = advance(q);
        if (rc != CH_OK) {
            return quic_fail(q, rc);
        }
        // A step that moved rx_level consumed the whole delivery. A byte
        // left over is data at a level this server has left, which RFC
        // 9001 section 4.1.3 makes a connection error of type
        // PROTOCOL_VIOLATION (rfc9001.txt:488-493), or 0x010a when it
        // opens a KeyUpdate.
        if (q->rx_level != was && (q->t.pt_off != q->t.pt_len || off != n)) {
            return quic_fail(q, quic_refuse_unread(q));
        }
    }
}

int ch_srv_quic_init(ch_quic *q, const ch_cfg *cfg) {
    memset(q, 0, sizeof *q);
    q->t.cfg = *cfg;
    if (!srv_config_ok(cfg)) {
        // Nothing went out and no secret was drawn, so a zeroed q with a
        // dead state is the whole answer.
        memset(q, 0, sizeof *q);
        q->t.state = CH_ST_FAILED;
        return CH_EINVAL;
    }
    q->hs.t = &q->t;
    // The description a failure carries when no handler chose a more
    // specific one, seeded the way srv_handshake.c seeds it.
    q->hs.alert = ALERT_DECODE_ERROR;
    q->endpoint = CH_QUIC_ENDPOINT_SERVER;
    // 0 is the first protocol in ch_cfg.alpn_protocols, so the
    // no-selection value has to be written before the parser can report
    // one.
    q->t.alpn_selected = CH_ALPN_NONE;
    // Draws this connection's key share. A client build does the same in
    // ch_quic_init; a server has no hello to build with it yet.
    srv_begin(&q->hs);
    q->step = SQ_STEP_AWAIT_CLIENT_HELLO;
    q->rx_level = CH_LEVEL_INITIAL;
    q->t.state = CH_ST_START;
    return CH_OK;
}

int ch_srv_quic_crypto_in(ch_quic *q, uint8_t level, const uint8_t *p, size_t n) {
    CH_ASSERT(q->t.state <= CH_ST_FAILED);
    q->hs.t = &q->t;
    if (session_dead(q)) {
        return CH_EPROTO;
    }
    if (level > CH_LEVEL_APPLICATION) {
        return CH_EINVAL;
    }
    if (level > q->rx_level) {
        // Bytes for a level whose keys are not installed are QUIC's to
        // hold (rfc9001.txt:488-490), so an empty buffer is no error and
        // the caller may deliver them again. Bytes sitting unread at the
        // lower level make it one (rfc9001.txt:491-493).
        return q->t.pt_off == q->t.pt_len ? CH_EINVAL : quic_fail_level(q);
    }
    if (level < q->rx_level) {
        return quic_fail_level(q);
    }
    return drive(q, p, n);
}

void ch_srv_quic_retry_tag(const uint8_t *pseudo, size_t n, uint8_t *tag) {
    quic_retry_tag(pseudo, n, tag);
}

#endif // CH_ROLE_SERVER && CH_TRANSPORT_QUIC_NONBLOCKING
