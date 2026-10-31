// Proves: ch_record_init, ch_record_in, ch_record_out and ch_record_close
// (tcp_nonblocking.c), the step table under them (tcp_nonblocking_step.c)
// and the framing and death path both tcp-nonblocking drivers share
// (tcp_nonblocking_frame.c) are memory safe and free of UB over an
// unconstrained ch_cfg, saved state and caller bytes. And that the
// client driver keeps what tcp_nonblocking.h states:
// - init answers CH_OK with the ClientHello staged as one plaintext
//   record and the session at its first step, or CH_EINVAL with a dead
//   session and nothing staged (INV-13);
// - a step number no step wrote kills the session with
//   unexpected_message, and a second HelloRetryRequest does too;
// - the Finished step stages the client Finished, wipes the handshake
//   state and writes the back pointer again (INV-17);
// - ch_record_in never reports more bytes than it was handed, refuses
//   input while a record is staged, and leaves a failed session dead,
//   with no secret and at most its alert record staged (INV-13, INV-17);
// - ch_record_out hands over at most cap bytes, and the session is
//   connected only after the last byte of the client Finished;
// - ch_record_close leaves a closed session with no secret and nothing
//   staged, which ch_record_state reports.
//
// What is real and what is a stub. The three driver files and ct.c are
// real. The handshake_flight.h and handshake_auth.h handlers are stubs,
// as in proof/quic_step_harness.c: each asserts what its header requires
// and havocs what its header writes, and handshake_psk and handshake_pin
// prove the handlers. rec_open, rec_seal, rec_dir_init and the
// handshake_record.h calls are stubs, as in
// proof/srv_tcp_nonblocking_harness.c. tlsi_config_ok and
// tlsi_epoch_init are stubs to tls.c's contract. ct_wipe writes its zeros
// with one memset, for the reason that harness gives; ct proves the body.
//
// Bounds. CH_PROOF_RXBUF is 8, two smallest messages. CH_PROOF_INBUF is
// 13: one record of a 5-byte header and two 4-byte messages, or two
// empty records and a partial third. The record loop and the message
// loop each run at most 3 times, so unwind 4 covers both.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include <string.h>

#include "handshake_auth.h"
#include "handshake_flight.h"
#include "handshake_message.h"
#include "handshake_record.h"
#include "record.h"
#include "tcp_nonblocking.h"
#include "tcp_nonblocking_frame.h"
#include "tcp_nonblocking_step.h"

#ifndef CH_PROOF_RXBUF
#define CH_PROOF_RXBUF 8
#endif
#ifndef CH_PROOF_INBUF
#define CH_PROOF_INBUF 13
#endif

int nondet_int(void);
uint16_t nondet_u16(void);

static uint8_t buf[CH_PROOF_RXBUF];
static uint8_t in[CH_PROOF_INBUF];
static uint8_t out[CH_PROOF_INBUF];
static ch_record r;
static ch_cfg cfg;
static ch_saved_ticket saved;

// Every handler answers CH_OK or a code its header lists, and writes
// h->alert on failure. A failure leaves the session to the driver.
static int handler_result(handshake_state *h) {
    int rc = nondet_int();
    __CPROVER_assume(rc == CH_OK || rc == CH_EPROTO || rc == CH_EAUTH || rc == CH_ECAP ||
                     rc == CH_EINVAL);
    if (rc != CH_OK) {
        h->alert = nondet_u8();
    }
    return rc;
}

// The reader every handler goes through. The driver runs a step only
// after hsr_peek_message saw a whole message at pt_off, so a handler
// that succeeds consumes at least its 4-byte header.
static int take_message(handshake_state *h) {
    __CPROVER_assert(h != NULL && h->t == &r.t, "msg: the session's state");
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

void hsf_begin(handshake_state *h) {
    __CPROVER_assert(h->t == &r.t, "begin: the session's state");
    fill_nondet(h->priv, sizeof h->priv);
    fill_nondet(h->pub, sizeof h->pub);
}

size_t hsf_build_client_hello(handshake_state *h, uint8_t *dst, size_t cap) {
    __CPROVER_assert(__CPROVER_w_ok(h, sizeof *h), "hello: state writable");
    __CPROVER_assert(dst == r.t.tx + REC_HDR && cap == sizeof r.t.tx - REC_HDR,
                     "hello: staged after the record header");
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= cap && n <= 0xffff);
    if (n == 0) {
        h->alert = ALERT_INTERNAL_ERROR;
    }
    return n;
}

int hsf_read_server_hello(handshake_state *h, server_hello_info *info) {
    __CPROVER_assert(__CPROVER_w_ok(info, sizeof *info), "server hello: info writable");
    int rc = take_message(h);
    if (rc != CH_OK) {
        return rc;
    }
    memset(info, 0, sizeof *info);
    info->hrr = nondet_int();
    return CH_OK;
}

int hsf_accept_server_hello(handshake_state *h, const server_hello_info *info) {
    __CPROVER_assert(__CPROVER_r_ok(info, sizeof *info) && info->hrr == 0,
                     "accept: a ServerHello, not a HelloRetryRequest");
    int rc = handler_result(h);
    if (rc == CH_OK) {
        h->t->psk_selected = nondet_u8() & 1;
    }
    return rc;
}

int hsf_derive_handshake_secrets(handshake_state *h, const server_hello_info *info) {
    __CPROVER_assert(__CPROVER_r_ok(info, sizeof *info), "derive: info readable");
    int rc = handler_result(h);
    if (rc == CH_OK) {
        fill_nondet(h->c_hs, sizeof h->c_hs);
        fill_nondet(h->s_hs, sizeof h->s_hs);
    }
    return rc;
}

int hsf_read_encrypted_extensions(handshake_state *h) {
    return take_message(h);
}

int hsf_read_finished(handshake_state *h) {
    int rc = take_message(h);
    if (rc == CH_OK) {
        h->server_finished_ok = 1;
    }
    return rc;
}

size_t hsf_complete(handshake_state *h, uint8_t finished[HSF_FINISHED_MAX]) {
    __CPROVER_assert(h->server_finished_ok, "complete: the server Finished verified first");
    __CPROVER_assert(__CPROVER_w_ok(finished, HSF_FINISHED_MAX), "complete: staging writable");
    fill_nondet(r.t.wr_secret, sizeof r.t.wr_secret);
    fill_nondet(r.t.rd_secret, sizeof r.t.rd_secret);
    return 4 + SHA256_LEN; // the header and one SHA-256 verify_data
}

int hsa_server_auth(handshake_state *h) {
    return take_message(h);
}

int hsa_read_certificate_verify(handshake_state *h) {
    return take_message(h);
}

#ifdef CH_PROOF_STEP_STUB
// tcp_nonblocking_step.h's contract, which prove_advance proves of the
// real table: one whole message consumed, or the window emptied by the
// last step, and at most one record staged from its start; or a failure
// with the alert chosen.
int tcp_nonblocking_advance(ch_record *s) {
    __CPROVER_assert(s == &r && s->hs.t == &s->t, "advance: the session, back pointer set");
    __CPROVER_assert(s->t.pt_len >= 4 && s->t.pt_off <= s->t.pt_len - 4,
                     "advance: a whole message is unread");
    int rc = handler_result(&s->hs);
    if (rc != CH_OK) {
        return rc;
    }
    if (nondet_u8() & 1) {
        s->t.pt_off = 0;
        s->t.pt_len = 0;
    } else {
        size_t whole = nondet_size_t();
        __CPROVER_assume(whole >= 4 && whole <= s->t.pt_len - s->t.pt_off);
        s->t.pt_off += whole;
    }
    if (nondet_u8() & 1) {
        size_t staged = nondet_size_t();
        __CPROVER_assume(staged >= 1 && staged <= sizeof s->t.tx);
        s->tx_len = staged;
        s->tx_off = 0;
    }
    s->step = nondet_u8();
    s->t.keys = nondet_u8();
    return CH_OK;
}
#endif

#include "tcp_nonblocking_record_stubs.h"

// Two seals reach here: the client Finished into t.tx, and a failure's
// alert into the caller's record, both under the write key.
int rec_seal(rec_dir *d, uint8_t type, const uint8_t *pt, size_t n, uint8_t *dst, size_t cap,
             size_t *out_len) {
    __CPROVER_assert(d == &r.t.wr, "seal: under the write key");
    __CPROVER_assert(
        (type == REC_HANDSHAKE && n == 4 + SHA256_LEN && dst == r.t.tx && cap == sizeof r.t.tx) ||
            (type == REC_ALERT && n == 2 && r.t.keys != 0),
        "seal: the client Finished, or an alert before the wipe");
    __CPROVER_assert(__CPROVER_r_ok(pt, n) && __CPROVER_w_ok(dst, cap) && out_len != NULL,
                     "seal: buffers valid");
    if (nondet_u8() & 1) {
        return -1; // a short cap or the last sequence number
    }
    __CPROVER_assume(REC_OVERHEAD + n <= cap);
    *out_len = REC_OVERHEAD + n;
    return 0;
}

void rec_dir_init(rec_dir *d, const uint8_t secret[SHA256_LEN]) {
    __CPROVER_assert(d == &r.t.rd || d == &r.t.wr, "keys: one of the session's directions");
    __CPROVER_assert(__CPROVER_r_ok(secret, SHA256_LEN), "keys: secret readable");
    fill_nondet((uint8_t *)d, sizeof *d);
}

// handshake_post.h: whether cfg still holds the trust the ticket names.
int hspost_trust_holds(const ch_cfg *c, const ch_ticket *ticket) {
    __CPROVER_assert(__CPROVER_r_ok(c, sizeof *c) && __CPROVER_r_ok(ticket, sizeof *ticket),
                     "trust: cfg and ticket readable");
    return nondet_u8() & 1;
}

// tls.c's contract: a configuration it accepts names a buffer of at
// least CH_MIN_RXBUF bytes.
int tlsi_config_ok(const ch_cfg *c) {
    if (nondet_u8() & 1) {
        return 0;
    }
    __CPROVER_assume(c->buf != NULL && c->buf_len >= CH_MIN_RXBUF);
    return 1;
}

int tlsi_epoch_init(ch_tls *t, const ch_cfg *c, int psk_ok) {
    __CPROVER_assert(t == &r.t && c == &r.t.cfg, "epoch: the session's own copy");
    (void)psk_ok;
    return (nondet_u8() & 1) ? CH_OK : CH_EINVAL;
}

void ct_wipe(void *p, size_t n) {
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(p, n), "wipe: the bytes are writable");
    if (n != 0) {
        memset(p, 0, n);
    }
}

static int send_cb(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    return (int)n;
}

static int recv_cb(void *io, uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    return (int)n;
}

// Whether the session holds any secret, tcp_nonblocking_frame.h's list
// read back.
static int no_secret_left(const ch_record *s) {
    for (size_t i = 0; i < sizeof s->t.rd_secret; i++) {
        if (s->t.rd_secret[i] != 0 || s->t.wr_secret[i] != 0 || s->t.res_master[i] != 0) {
            return 0;
        }
    }
    return s->t.keys == 0;
}

// A saved state with every field a call reads havocked.
static void havoc_state(void) {
    memset(&r, 0, sizeof r);
    r.t.cfg = cfg;
    r.t.cfg.buf = buf;
    r.t.cfg.buf_len = sizeof buf;
    r.hs.t = &r.t;
    fill_nondet(buf, sizeof buf);
    fill_nondet(r.t.rd_secret, sizeof r.t.rd_secret);
    fill_nondet(r.t.wr_secret, sizeof r.t.wr_secret);
    r.step = nondet_u8();
    r.hs.alert = nondet_u8();
    r.hs.encrypted = nondet_int();
    r.t.keys = nondet_u8();
    uint8_t state = nondet_u8();
    __CPROVER_assume(state <= CH_ST_FAILED);
    r.t.state = state;
    size_t off = nondet_size_t();
    size_t len = nondet_size_t();
    __CPROVER_assume(len <= sizeof buf && off <= len);
    r.t.pt_off = off;
    r.t.pt_len = len;
}

static void prove_init(void) {
    memset(&cfg, 0, sizeof cfg);
    cfg.buf = (nondet_u8() & 1) ? buf : NULL;
    cfg.buf_len = nondet_size_t();
    cfg.send = (nondet_u8() & 1) ? send_cb : NULL;
    cfg.recv = (nondet_u8() & 1) ? recv_cb : NULL;
    if (nondet_u8() & 1) {
        saved.ticket.psk_len = nondet_size_t();
        saved.ticket.lifetime_s = nondet_u32();
        cfg.ticket = &saved;
    }
    int rc = ch_record_init(&r, &cfg);
    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL, "init answers one of its two codes");
    if (rc == CH_EINVAL) {
        __CPROVER_assert(r.t.state == CH_ST_FAILED && r.tx_len == 0 && no_secret_left(&r),
                         "a refused configuration leaves it dead, with nothing staged");
        return;
    }
    __CPROVER_assert(r.t.state == CH_ST_START && r.step == TCP_NONBLOCKING_STEP_AWAIT_SERVER_HELLO,
                     "a prepared session waits at the first step");
    __CPROVER_assert(r.hs.t == &r.t && r.tx_off == 0, "with the back pointer set");
    __CPROVER_assert(r.tx_len > REC_HDR && r.t.tx[0] == REC_HANDSHAKE &&
                         ((size_t)r.t.tx[3] << 8 | r.t.tx[4]) == r.tx_len - REC_HDR,
                     "the ClientHello is staged as one plaintext record");
    __CPROVER_assert(r.hs.record_size_limit <= 0x4001 &&
                         r.hs.record_size_limit <= r.t.cfg.buf_len - REC_HDR - AEAD_TAG,
                     "its record_size_limit fits the caller's buffer");
}

static void prove_advance(void) {
    havoc_state();
    __CPROVER_assume(r.t.pt_len - r.t.pt_off >= 4); // what drive checked
    uint8_t was_step = r.step;
    size_t off = r.t.pt_off;
    int rc = tcp_nonblocking_advance(&r);
    __CPROVER_assert(r.t.pt_off <= r.t.pt_len && r.t.pt_len <= r.t.cfg.buf_len,
                     "a step leaves the window inside the buffer");
    if (was_step > TCP_NONBLOCKING_STEP_COMPLETE || was_step == TCP_NONBLOCKING_STEP_COMPLETE) {
        __CPROVER_assert(rc == CH_EPROTO && r.hs.alert == ALERT_UNEXPECTED_MESSAGE,
                         "no step runs past the table's end");
    }
    __CPROVER_assert(r.hs.t == &r.t, "the back pointer stays set");
    __CPROVER_assert(r.tx_off == 0 && r.tx_len <= sizeof r.t.tx, "a staged record starts at 0");
    if (rc == CH_OK) {
        __CPROVER_assert(r.t.pt_off > off || (was_step == TCP_NONBLOCKING_STEP_AWAIT_FINISHED &&
                                              r.t.pt_off == 0 && r.t.pt_len == 0),
                         "a step consumes its message, and the last one empties the window");
        if (was_step == TCP_NONBLOCKING_STEP_AWAIT_RETRY_HELLO) {
            __CPROVER_assert(r.step != TCP_NONBLOCKING_STEP_AWAIT_RETRY_HELLO,
                             "a second HelloRetryRequest is refused");
        }
        if (was_step == TCP_NONBLOCKING_STEP_AWAIT_FINISHED) {
            __CPROVER_assert(r.step == TCP_NONBLOCKING_STEP_COMPLETE && r.hs.t == &r.t,
                             "the Finished step ends the handshake");
            __CPROVER_assert(r.tx_len == REC_OVERHEAD + 4 + SHA256_LEN && r.tx_off == 0,
                             "with the client Finished staged");
            __CPROVER_assert(r.hs.server_finished_ok == 0, "and the handshake state wiped");
        }
    }
}

static void prove_in(void) {
    havoc_state();
    r.tx_len = (nondet_u8() & 1) ? (size_t)REC_HDR : 0;
    fill_nondet(in, sizeof in);
    int was_dead = tcp_nonblocking_session_dead(&r);
    size_t was_staged = r.tx_len;
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof in);
    size_t consumed = nondet_size_t();
    int rc = ch_record_in(&r, in, n, &consumed);
    __CPROVER_assert(consumed <= n, "it never reports more bytes than it was handed");
    __CPROVER_assert(r.t.pt_off <= r.t.pt_len && r.t.pt_len <= r.t.cfg.buf_len,
                     "and leaves the window inside the buffer");
    if (was_dead) {
        __CPROVER_assert(rc == CH_EPROTO && consumed == 0, "a dead session refuses the call");
    } else if (was_staged != 0) {
        __CPROVER_assert(rc == CH_EINVAL && consumed == 0, "a staged record refuses input");
    } else if (rc != CH_OK) {
        __CPROVER_assert(tcp_nonblocking_session_dead(&r) && no_secret_left(&r),
                         "a failure leaves the session dead and holding no secret");
        __CPROVER_assert(r.tx_off == 0 && r.tx_len <= CH_ALERT_RECORD_LEN,
                         "with at most its alert record staged");
        __CPROVER_assert(r.t.alert_received == 0 || r.tx_len == 0,
                         "no alert after the peer's fatal alert");
    }
}

static void prove_out(void) {
    havoc_state();
    size_t len = nondet_size_t();
    size_t off = nondet_size_t();
    __CPROVER_assume(len <= sizeof r.t.tx && off <= len);
    r.tx_len = len;
    r.tx_off = off;
    size_t cap = nondet_size_t();
    __CPROVER_assume(cap <= sizeof out);
    uint8_t was_state = r.t.state;
    size_t out_len = nondet_size_t();
    int rc = ch_record_out(&r, out, cap, &out_len);
    if (rc == CH_OK && len > off) {
        size_t want = len - off < cap ? len - off : cap;
        __CPROVER_assert(out_len == want, "it hands over the next staged bytes, at most cap");
    }
    __CPROVER_assert(r.tx_off <= r.tx_len, "the staging window stays ordered");
    if (r.t.state == CH_ST_CONNECTED && was_state != CH_ST_CONNECTED) {
        __CPROVER_assert(r.step == TCP_NONBLOCKING_STEP_COMPLETE && r.tx_len == 0,
                         "connected only after the last Finished byte");
    }
}

int main(void) {
#ifdef CH_PROOF_STEP_STUB
    prove_in();
#else
    prove_init();
    prove_advance();
    prove_out();
    havoc_state();
    ch_record_close(&r);
    __CPROVER_assert(r.t.state == CH_ST_CLOSED && r.tx_len == 0 && no_secret_left(&r),
                     "a closed session holds no secret and stages nothing");
    __CPROVER_assert(ch_record_state(&r) == CH_ST_CLOSED, "and reports itself closed");
#endif
    return 0;
}
