// Proves: ch_srv_record_init, ch_srv_record_in and the step table under
// them (srv_tcp_nonblocking.c), together with the inbound framing and the
// death path both tcp-nonblocking drivers share
// (tcp_nonblocking_frame.c), are memory safe and free of UB over an
// unconstrained ch_cfg, an unconstrained saved state and unconstrained
// caller bytes. And that the driver keeps what srv_tcp_nonblocking.h
// states: it takes whole records only, it never reports more bytes than
// it was handed, a step number no step wrote kills the session, and every
// failure pushes at most one record, its alert, sealed only before its
// wipe (INV-13), and leaves a dead session holding no secret (INV-17).
//
// What is real and what is a stub. srv_tcp_nonblocking.c,
// tcp_nonblocking_frame.c and ct.c are real, so the proof covers the step
// table, the record loop, the message loop and the wipe on the way out.
// The fifteen srv_flight.h handlers are stubs, for
// proof/srv_accept_harness.c's reason: a handler and the driver that
// calls it are separate proofs, and inlining fifteen message builders
// would make this a parser proof rather than a driver proof. Each stub
// asserts the contract its own header states and havocs what that header
// says it writes, so nothing here rests on one handler's implementation.
// rec_open, rec_seal and hsr_feed are stubs for the same reason
// proof/handshake_post_harness.c stubs them: record protection belongs to
// record.c's harness and reassembly to handshake_record.c's. srv_out_alert
// states srv_out.h's contract and counts the records a failure pushes.
//
// The pairing with srv_flight. proof/srv_flight_harness.c turns this
// layering around -- there the handlers are real and the driver is the
// stub -- so the two read as a pair: what this harness assumes of a handler
// is what that one discharges. It is the pairing quic_driver and
// quic_step already have.
//
// Bounds. CH_PROOF_RXBUF is 8: two smallest messages. CH_PROOF_INBUF is
// 13: one record of a 5-byte header and two 4-byte messages, or two empty
// records and a partial third. At 8 bytes no record held a whole message,
// so ch_srv_record_in never reached the step table, and a cover run
// showed it. The record loop and the message loop each run at most 3
// times, so unwind 4 covers both.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include <string.h>

#include "handshake_message.h"
#include "handshake_record.h"
#include "record.h"
#include "srv_flight.h"
#include "srv_resume.h"
#include "srv_tcp_nonblocking.h"
#include "tcp_nonblocking_frame.h"

#ifndef CH_PROOF_RXBUF
#define CH_PROOF_RXBUF 8
#endif
#ifndef CH_PROOF_INBUF
#define CH_PROOF_INBUF 13
#endif

int nondet_int(void);
uint16_t nondet_u16(void);

#include "srv_flight_stubs.h"

#include "tcp_nonblocking_record_stubs.h"

#include "srv_tcp_nonblocking.c"

static uint8_t buf[CH_PROOF_RXBUF];
static uint8_t in[CH_PROOF_INBUF];
static ch_record r;
static ch_cfg cfg;
static size_t records_pushed; // srv_out_alert's calls, all a failure's

// tcp_nonblocking_fail's seal of one fatal alert, under a live write key:
// the wipe after the seal clears ch_tls.keys, so a seal after it fails.
int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *out, size_t cap,
             size_t *out_len) {
    __CPROVER_assert(r.t.keys != 0 && d == &r.t.wr, "seal: under the write key, before the wipe");
    __CPROVER_assert(type == REC_ALERT && n == 2 && __CPROVER_r_ok(pt, n) &&
                         cap >= REC_OVERHEAD + n && __CPROVER_w_ok(out, cap) && out_len != NULL,
                     "seal: one alert into a record it fits");
    if (nondet_u8() & 1) {
        return -1; // the last sequence number (RFC 9846 section 5.3)
    }
    fill_nondet(out, REC_OVERHEAD + n);
    *out_len = REC_OVERHEAD + n;
    return 0;
}

// srv_out.h's best-effort push of a failure's alert record to
// cfg.srv.on_record_out, which reports nothing back.
void srv_out_alert(ch_tls *t, const uint8_t *rec, size_t n) {
    __CPROVER_assert(t == &r.t && n >= REC_HDR && n <= CH_ALERT_RECORD_LEN &&
                         __CPROVER_r_ok(rec, n),
                     "push: one alert record of the session under proof");
    records_pushed++;
}

// cfg.srv.on_record_out. srv_config_ok refuses a NULL, so srv_out.c's
// emit calls it without a check; this harness compiles no handler, so
// nothing reaches it and it needs a body only to have an address.
static int sink(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    return 0;
}

// ct_wipe's contract (ct.h): it writes zero to p[0..n) and no other byte.
// The ct harness proves the body that proof/ct_wipe_stub.c holds. That
// body stores one byte a pass, and the failure path wipes the 1,221 bytes
// of ch_tls.tx: unrolled on every failure path, it took the formula to
// 11.8 GB, and kissat died. One memset writes the same bytes, and CBMC
// writes it to the array whole.
void ct_wipe(void *p, size_t n) {
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(p, n), "wipe: the bytes are writable");
    if (n != 0) {
        memset(p, 0, n);
    }
}

// Whether the session holds any secret. tcp_nonblocking_frame.h says a failure
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
        // srv_tcp_nonblocking.h: nothing was sent and the session
        // is dead rather than half-live.
        __CPROVER_assert(r.t.state == CH_ST_FAILED, "a refused configuration leaves it dead");
    }
    if (rc == CH_OK) {
        __CPROVER_assert(r.t.state == CH_ST_START, "a prepared session waits");
        __CPROVER_assert(r.step == SRV_TCP_NONBLOCKING_STEP_AWAIT_CLIENT_HELLO,
                         "at the first step");
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
    // ch_srv_record_init writes CH_TX_PT and only srv_store_selection
    // writes it after that, never higher, so no saved state holds more.
    r.t.peer_limit = nondet_u16();
    __CPROVER_assume(r.t.peer_limit <= CH_TX_PT);
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
    if (was_step > SRV_TCP_NONBLOCKING_STEP_COMPLETE) {
        __CPROVER_assert(rc == CH_EPROTO, "a step number no step wrote kills the session");
        __CPROVER_assert(r.hs.alert == ALERT_UNEXPECTED_MESSAGE, "and names unexpected_message");
        __CPROVER_assert(r.step == was_step && r.t.pt_off == off, "and changes nothing else");
    }
    if (rc == CH_OK) {
        __CPROVER_assert(was_step <= SRV_TCP_NONBLOCKING_STEP_COMPLETE,
                         "only a step in the table can succeed");
        __CPROVER_assert(r.t.pt_off > off, "a step consumes its message");
        if (was_step == SRV_TCP_NONBLOCKING_STEP_AWAIT_CLIENT_FINISHED) {
            __CPROVER_assert(r.step == SRV_TCP_NONBLOCKING_STEP_COMPLETE,
                             "the Finished step ends the handshake");
            __CPROVER_assert(r.hs.t == &r.t, "and writes the back pointer again after the wipe");
        }
    }

    // The public entry, over unconstrained caller bytes and the saved
    // state again havocked. n runs past the array on purpose only as far
    // as the array: a caller that lies about n is outside the contract
    // srv_tcp_nonblocking.h states, so the assume holds it to the object.
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
    int was_dead = tcp_nonblocking_session_dead(&r);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof in);
    size_t consumed = nondet_size_t();

    rc = ch_srv_record_in(&r, in, n, &consumed);

    __CPROVER_assert(consumed <= n, "it never reports more bytes than it was handed");
    __CPROVER_assert(r.t.pt_off <= r.t.pt_len && r.t.pt_len <= r.t.cfg.buf_len,
                     "and leaves the window inside the buffer");
    __CPROVER_assert(records_pushed <= (size_t)(rc != CH_OK), "only a failure pushes: its alert");
    if (was_dead) {
        // A refusal on entry (INV-13): the call changes nothing and sends
        // nothing, and the session stays as dead as it was.
        __CPROVER_assert(rc == CH_EPROTO && consumed == 0 && records_pushed == 0,
                         "a dead session refuses the call and pushes nothing");
    } else if (rc != CH_OK) {
        // tcp_nonblocking_frame.h's death path: no alert after the peer's
        // fatal alert, every secret cleared and the session dead.
        __CPROVER_assert(r.t.alert_received == 0 || records_pushed == 0,
                         "no alert after the peer's fatal alert");
        __CPROVER_assert(tcp_nonblocking_session_dead(&r), "a failure leaves the session dead");
        __CPROVER_assert(no_secret_left(&r), "and holds no secret (INV-17)");
    }
    return 0;
}
