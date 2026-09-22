// Proves: ch_srv_record_init, ch_srv_record_in and the step table under
// them (srv_rec.c), together with the inbound framing and the death path
// both record-mode drivers share (rec_frame.c), are memory safe and free
// of UB over an unconstrained ch_cfg, an unconstrained saved state and
// unconstrained caller bytes. And that the driver keeps what srv_rec.h
// states: it takes whole records only, it never reports more bytes than
// it was handed, a step number no step wrote kills the session, and every
// failure leaves a dead session holding no secret (INV-17).
//
// What is real and what is a stub. srv_rec.c, rec_frame.c and ct.c are
// real, so the proof covers the step table, the record loop, the message
// loop and the wipe on the way out. The fifteen srv_flight.h handlers are
// stubs, for proof/srv_accept_harness.c's reason: a handler and the
// driver that calls it are separate proofs, and inlining fifteen message
// builders would make this a parser proof rather than a driver proof.
// Each stub asserts the contract its own header states and havocs what
// that header says it writes, so nothing here rests on one handler's
// implementation. rec_open and hsr_feed are stubs for the same reason
// proof/handshake_post_harness.c stubs them: record protection belongs to
// record.c's harness and reassembly to handshake_record.c's.
//
// The pairing with srv_flight. proof/srv_flight_harness.c turns this
// layering around -- there the handlers are real and the driver is the
// stub -- so the two read as a pair: what this leg assumes of a handler
// is what that one discharges. It is the pairing quic_driver and
// quic_step already have.
//
// Bounds. CH_PROOF_RXBUF is 8 and CH_PROOF_INBUF is 8: one smallest
// record plus a partial second, and two smallest messages. Both are
// below handshake_record's own harness value of 12 for a measured
// reason. The two loops nest -- the record loop runs the message loop,
// which runs the step table -- so CBMC unrolls the global unwind
// squared, and at 12 bytes with unwind 8 that is 64 copies of the table,
// each carrying a 623-iteration wipe on its failure path. That formula
// had no verdict in 11 minutes at 1.36 GB. At 8 bytes the loops need 3
// iterations each, unwind 4 covers both, and 16 copies converge.
// ct_wipe.0 is 623, one past the 622 bytes of ch_tls.tx, the largest
// object rec_wipe clears.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include <string.h>

#include "handshake_message.h"
#include "handshake_record.h"
#include "rec_frame.h"
#include "record.h"
#include "srv_flight.h"
#include "srv_rec.h"

#ifndef CH_PROOF_RXBUF
#define CH_PROOF_RXBUF 8
#endif
#ifndef CH_PROOF_INBUF
#define CH_PROOF_INBUF 8
#endif

int nondet_int(void);
uint16_t nondet_u16(void);

// Every handler answers CH_OK or one of the codes its header lists, and
// writes h->alert on failure. srv_flight.h leaves a failed handler's
// session to the driver, so none of these wipes anything. CH_EIO is in
// the set because srv_out.c's emit reports a refusing sink that way, and
// every send below goes through it.
static int handler_result(handshake_state *h) {
    int rc = nondet_int();
    __CPROVER_assume(rc == CH_OK || rc == CH_EPROTO || rc == CH_EAUTH || rc == CH_ECAP ||
                     rc == CH_EINVAL || rc == CH_EIO);
    if (rc != CH_OK) {
        h->alert = nondet_u8();
    }
    return rc;
}

// The two handlers that read a message go through here. srv_rec.c runs a
// step only after hsr_peek_message has found a whole message, so that is
// what this asserts, and a message it yields is at least its own 4-byte
// header. Consuming is what makes drive's loop terminate, so a stub that
// answered CH_OK without advancing pt_off would prove a loop this driver
// does not run.
static int take_message(handshake_state *h) {
    __CPROVER_assert(h != NULL && h->t != NULL, "msg: state valid");
    __CPROVER_assert(h->t->pt_len >= 4 && h->t->pt_off <= h->t->pt_len - 4,
                     "msg: a whole message is unread");
    int rc = handler_result(h);
    if (rc != CH_OK) {
        return rc;
    }
    size_t whole = nondet_size_t();
    __CPROVER_assume(whole >= 4 && whole <= h->t->pt_len - h->t->pt_off);
    h->t->pt_off += whole;
    return CH_OK;
}

// srv.c's configuration rules. The answer is free, but a 1 carries what
// srv.h promises a caller that got one: the receive buffer is live and at
// this build's floor, and the record transport's own arm has checked that
// a sink is set. ch_srv_record_init reads all three on the strength of
// that answer, so a stub that answered 1 for any cfg at all would prove
// arithmetic the real predicate never admits.
int srv_config_ok(const ch_cfg *cfg) {
    __CPROVER_assert(__CPROVER_r_ok(cfg, sizeof *cfg), "config: cfg readable");
    if (nondet_u8() & 1) {
        return 0;
    }
    __CPROVER_assume(cfg->buf != NULL && cfg->buf_len >= CH_MIN_RXBUF);
    __CPROVER_assume(cfg->srv.on_record_out != NULL);
    return 1;
}

// Draws this connection's key share into the state the caller zeroed.
void srv_begin(handshake_state *h) {
    __CPROVER_assert(__CPROVER_w_ok(h, sizeof *h), "begin: state writable");
    __CPROVER_assert(h->t != NULL, "begin: the back pointer is set");
    fill_nondet(h->priv, sizeof h->priv);
    fill_nondet(h->pub, sizeof h->pub);
}

int srv_read_client_hello(handshake_state *h, client_hello *ch) {
    __CPROVER_assert(__CPROVER_w_ok(ch, sizeof *ch), "hello: parse target writable");
    int rc = take_message(h);
    if (rc != CH_OK) {
        return rc;
    }
    memset(ch, 0, sizeof *ch);
    // The two members store_selection reads. record_size_limit runs over
    // the whole uint16_t, so both sides of its boundary are in the
    // formula: a value below this build's cap is adopted and every
    // larger one leaves it standing.
    ch->record_size_limit = nondet_u16();
    ch->alpn_selected = nondet_u8();
    return CH_OK;
}

int srv_select(handshake_state *h, const client_hello *ch, selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "select: hello readable");
    __CPROVER_assert(__CPROVER_w_ok(sel, sizeof *sel), "select: selection writable");
    int rc = handler_result(h);
    if (rc != CH_OK) {
        return rc;
    }
    memset(sel, 0, sizeof *sel);
    sel->suite = nondet_u16();
    sel->hash_len = nondet_u8();
    sel->group = nondet_u16();
    sel->sigalg = nondet_u16();
    sel->need_retry = nondet_u8();
    sel->psk_selected = nondet_u8();
    return CH_OK;
}

int srv_check_retry_hello(handshake_state *h, const client_hello *ch, selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "retry: hello readable");
    __CPROVER_assert(__CPROVER_w_ok(sel, sizeof *sel), "retry: selection writable");
    int rc = handler_result(h);
    if (rc != CH_OK) {
        return rc;
    }
    memset(sel, 0, sizeof *sel);
    sel->suite = nondet_u16();
    sel->hash_len = nondet_u8();
    sel->group = nondet_u16();
    sel->sigalg = nondet_u16();
    sel->psk_selected = nondet_u8();
    // srv_flight.h: it never sets need_retry, which is what keeps a
    // second HelloRetryRequest unreachable. memset left it 0.
    return CH_OK;
}

int srv_send_hello_retry_request(handshake_state *h, const client_hello *ch, const selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "hrr: hello readable");
    __CPROVER_assert(__CPROVER_r_ok(sel, sizeof *sel), "hrr: selection readable");
    __CPROVER_assert(sel->need_retry, "hrr: the selection asked for a retry");
    return handler_result(h);
}

int srv_send_compat_ccs(handshake_state *h, const client_hello *ch) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "ccs: hello readable");
    return handler_result(h);
}

int srv_send_server_hello(handshake_state *h, const client_hello *ch, const selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "server hello: hello readable");
    __CPROVER_assert(__CPROVER_r_ok(sel, sizeof *sel), "server hello: selection readable");
    __CPROVER_assert(!sel->need_retry, "server hello: the retry is behind us");
    return handler_result(h);
}

int srv_derive_handshake_secrets(handshake_state *h, const client_hello *ch, const selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(ch, sizeof *ch), "derive: hello readable");
    __CPROVER_assert(__CPROVER_r_ok(sel, sizeof *sel), "derive: selection readable");
    int rc = handler_result(h);
    if (rc == CH_OK) {
        fill_nondet(h->c_hs, sizeof h->c_hs);
        fill_nondet(h->s_hs, sizeof h->s_hs);
        h->encrypted = 1;
        h->t->keys = 1;
    }
    return rc;
}

int srv_send_encrypted_extensions(handshake_state *h, const selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(sel, sizeof *sel), "ee: selection readable");
    return handler_result(h);
}

int srv_send_certificate(handshake_state *h, const selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(sel, sizeof *sel), "certificate: selection readable");
    __CPROVER_assert(!sel->psk_selected, "certificate: no PSK authenticated this handshake");
    return handler_result(h);
}

int srv_send_certificate_verify(handshake_state *h, const selection *sel) {
    __CPROVER_assert(__CPROVER_r_ok(sel, sizeof *sel), "cert verify: selection readable");
    __CPROVER_assert(!sel->psk_selected, "cert verify: no PSK authenticated this handshake");
    return handler_result(h);
}

int srv_send_finished(handshake_state *h) {
    int rc = handler_result(h);
    if (rc == CH_OK) {
        // The application write key goes in here, one round trip before
        // the read key (srv_flight.c:425).
        fill_nondet(h->t->wr_secret, sizeof h->t->wr_secret);
    }
    return rc;
}

// srv_flight.h requires a srv_read_client_finished that answered CH_OK
// before srv_complete runs, and the server holds that order by call
// position rather than by a flag: handshake_state carries
// server_finished_ok for the client's side and no counterpart. So the
// order is counted here, the way proof/srv_accept_harness.c counts
// handler calls.
static int finished_read;

int srv_read_client_finished(handshake_state *h) {
    int rc = take_message(h);
    if (rc == CH_OK) {
        finished_read++;
    }
    return rc;
}

void srv_complete(handshake_state *h) {
    __CPROVER_assert(finished_read > 0, "complete: the client Finished verified first");
    fill_nondet(h->t->rd_secret, sizeof h->t->rd_secret);
    h->t->state = CH_ST_CONNECTED;
}

// Reassembly, proven in handshake_record.c's own harness. It writes
// nothing outside cfg.buf, pt_off and pt_len, and it cannot fail: a short
// count is what rec_take_record reads as a record over the limit.
size_t hsr_feed(handshake_state *h, const uint8_t *p, size_t n) {
    __CPROVER_assert(h != NULL && h->t != NULL, "feed: state valid");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(p, n), "feed: plaintext readable");
    size_t room = h->t->cfg.buf_len - h->t->pt_len;
    size_t took = n <= room ? n : room;
    h->t->pt_len += took;
    return took;
}

// The message header check, proven with the reassembly it reads. It
// answers HSR_INCOMPLETE while the unread bytes stop short of a whole
// message, which is what ends the driver's loop.
int hsr_peek_message(const handshake_state *h, size_t *raw_len, uint8_t *alert) {
    __CPROVER_assert(h != NULL && h->t != NULL, "peek: state valid");
    __CPROVER_assert(raw_len != NULL && alert != NULL, "peek: outputs valid");
    __CPROVER_assert(h->t->pt_off <= h->t->pt_len, "peek: the window is ordered");
    if (h->t->pt_len - h->t->pt_off < 4) {
        return HSR_INCOMPLETE;
    }
    int rc = nondet_int();
    __CPROVER_assume(rc == CH_OK || rc == HSR_INCOMPLETE || rc == CH_EPROTO);
    if (rc == CH_EPROTO) {
        *alert = nondet_u8();
        return rc;
    }
    if (rc == CH_OK) {
        size_t whole = nondet_size_t();
        __CPROVER_assume(whole >= 4 && whole <= h->t->pt_len - h->t->pt_off);
        *raw_len = whole;
    }
    return rc;
}

// Record protection, proven in record.c's harness. rec_frame.c calls it
// with pt == rec, which is the in-place shape rec.h admits, so the
// assertion below is the aliasing this caller really uses.
int rec_open(rec_dir *d, const uint8_t *rec, size_t rec_len, uint8_t *pt, size_t pt_cap,
             size_t *pt_len, uint8_t *inner) {
    __CPROVER_assert(__CPROVER_w_ok(d, sizeof *d), "open: dir writable");
    __CPROVER_assert(__CPROVER_r_ok(rec, rec_len), "open: record readable");
    __CPROVER_assert(pt_cap == 0 || __CPROVER_w_ok(pt, pt_cap), "open: plaintext writable");
    __CPROVER_assert(pt_len != NULL && inner != NULL, "open: outputs valid");
    if (nondet_u8() & 1) {
        return -1;
    }
    size_t opened = nondet_size_t();
    __CPROVER_assume(opened <= pt_cap);
    fill_nondet(pt, opened);
    *pt_len = opened;
    *inner = nondet_u8();
    return 0;
}

#include "srv_rec.c"

static uint8_t buf[CH_PROOF_RXBUF];
static uint8_t in[CH_PROOF_INBUF];
static ch_record r;
static ch_cfg cfg;

// cfg.srv.on_record_out. srv_config_ok refuses a NULL, so srv_out.c's
// emit calls it without a check; this harness compiles no handler, so
// nothing reaches it and it needs a body only to have an address.
static int sink(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    return 0;
}

// Whether the session holds any secret. rec_frame.h says a failure
// clears every one of them, and this is that list read back.
static int no_secret_left(const ch_record *s) {
    for (size_t i = 0; i < sizeof s->t.rd_secret; i++) {
        if (s->t.rd_secret[i] != 0 || s->t.wr_secret[i] != 0 || s->t.res_master[i] != 0) {
            return 0;
        }
    }
    return s->t.keys == 0;
}

int main(void) {
    // The configuration, unconstrained but for the sink srv_config_ok
    // promises. ch_srv_record_init reads it and nothing else.
    memset(&cfg, 0, sizeof cfg);
    cfg.buf = (nondet_u8() & 1) ? buf : NULL;
    cfg.buf_len = nondet_size_t();
    cfg.srv.on_record_out = (nondet_u8() & 1) ? sink : NULL;

    int rc = ch_srv_record_init(&r, &cfg);
    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL, "init answers one of its two codes");
    if (rc == CH_EINVAL) {
        // srv_rec.h: nothing was sent and the session is dead rather
        // than half-live.
        __CPROVER_assert(r.t.state == CH_ST_FAILED, "a refused configuration leaves it dead");
    }
    if (rc == CH_OK) {
        __CPROVER_assert(r.t.state == CH_ST_START, "a prepared session waits");
        __CPROVER_assert(r.step == SR_STEP_AWAIT_CLIENT_HELLO, "at the first step");
        __CPROVER_assert(r.hs.t == &r.t, "with the back pointer set");
        __CPROVER_assert(r.t.peer_limit <= CH_TX_PT, "and this build's own send cap");
    }

    // The step table, over a step number no step wrote as well as the
    // four that exist. Every operand is havocked again here, because the
    // state init produced is one state and the table's default arm is
    // reachable only from the others.
    memset(&r, 0, sizeof r);
    r.t.cfg = cfg;
    r.t.cfg.buf = buf;
    r.t.cfg.buf_len = sizeof buf;
    r.t.cfg.srv.on_record_out = sink;
    r.hs.t = &r.t;
    fill_nondet(buf, sizeof buf);
    r.step = nondet_u8();
    r.hs.alert = nondet_u8();
    r.hs.encrypted = nondet_int();
    r.t.peer_limit = nondet_u16();
    // Two wrap-free clauses, not off + 4 <= len: that also holds for an
    // off near SIZE_MAX, and the window would then leave the buffer.
    size_t off = nondet_size_t();
    size_t len = nondet_size_t();
    __CPROVER_assume(len >= 4 && len <= sizeof buf);
    __CPROVER_assume(off <= len - 4);
    r.t.pt_off = off;
    r.t.pt_len = len;
    uint8_t was_step = r.step;

    rc = advance(&r);

    __CPROVER_assert(r.t.pt_off <= r.t.pt_len && r.t.pt_len <= r.t.cfg.buf_len,
                     "a step leaves the window inside the buffer");
    __CPROVER_assert(r.t.peer_limit <= CH_TX_PT,
                     "the client's record_size_limit never raises the send cap");
    if (was_step > SR_STEP_COMPLETE) {
        __CPROVER_assert(rc == CH_EPROTO, "a step number no step wrote kills the session");
        __CPROVER_assert(r.hs.alert == ALERT_UNEXPECTED_MESSAGE, "and names unexpected_message");
        __CPROVER_assert(r.step == was_step && r.t.pt_off == off, "and changes nothing else");
    }
    if (rc == CH_OK) {
        __CPROVER_assert(was_step <= SR_STEP_COMPLETE, "only a step in the table can succeed");
        __CPROVER_assert(r.t.pt_off > off, "a step consumes its message");
        if (was_step == SR_STEP_AWAIT_CLIENT_FINISHED) {
            __CPROVER_assert(r.step == SR_STEP_COMPLETE, "the Finished step ends the handshake");
            __CPROVER_assert(r.hs.t == &r.t, "and writes the back pointer again after the wipe");
        }
    }

    // The public entry, over unconstrained caller bytes and the saved
    // state again havocked. n runs past the array on purpose only as far
    // as the array: a caller that lies about n is outside the contract
    // srv_rec.h states, so the assume holds it to the object.
    memset(&r, 0, sizeof r);
    r.t.cfg = cfg;
    r.t.cfg.buf = buf;
    r.t.cfg.buf_len = sizeof buf;
    r.t.cfg.srv.on_record_out = sink;
    r.hs.t = &r.t;
    fill_nondet(buf, sizeof buf);
    fill_nondet(in, sizeof in);
    fill_nondet(r.t.rd_secret, sizeof r.t.rd_secret);
    fill_nondet(r.t.wr_secret, sizeof r.t.wr_secret);
    r.step = nondet_u8();
    r.hs.alert = nondet_u8();
    r.hs.encrypted = nondet_int();
    r.t.keys = nondet_u8();
    r.t.peer_limit = nondet_u16();
    uint8_t state = nondet_u8();
    __CPROVER_assume(state <= CH_ST_FAILED);
    r.t.state = state;
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof in);
    size_t consumed = nondet_size_t();

    rc = ch_srv_record_in(&r, in, n, &consumed);

    __CPROVER_assert(consumed <= n, "it never reports more bytes than it was handed");
    __CPROVER_assert(r.t.pt_off <= r.t.pt_len && r.t.pt_len <= r.t.cfg.buf_len,
                     "and leaves the window inside the buffer");
    if (rc != CH_OK) {
        // rec_frame.h's death path: the alert is saved for the caller to
        // send, every secret is cleared and the session is dead.
        __CPROVER_assert(rec_session_dead(&r), "a failure leaves the session dead");
        __CPROVER_assert(no_secret_left(&r), "and holds no secret (INV-17)");
    }
    return 0;
}
