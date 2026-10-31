// Contract stubs for the five srv_out.h calls the flight handlers make:
// srv_out_plain, srv_out_record, srv_out_sealed, srv_frag_bytes and
// srv_frag_flush. proof/srv_flight_harness.c includes this after its own
// helpers, whose nondet_int and fill_nondet it reads. It is a header of
// its own because that harness sits at the 500-line cap.
//
// Each stub asserts the bytes srv_out.h reads are readable and answers
// with every result srv_out.h allows: CH_OK, or a refusal with
// internal_error in h->alert. The record loops, the seal and the send are
// srv_out.c's, and this formula holds none of them: proof/srv_out_harness.c
// proves them.
#ifndef CH_SRV_OUT_STUBS_H
#define CH_SRV_OUT_STUBS_H

#include "srv_out.h"

// CH_OK, or a code from allowed with internal_error written first.
static int out_result(handshake_state *h, int allow_ecap) {
    if ((nondet_u8() & 1) != 0) {
        return CH_OK;
    }
    h->alert = ALERT_INTERNAL_ERROR;
    return (allow_ecap && (nondet_u8() & 1) != 0) ? CH_ECAP : CH_EIO;
}

int srv_out_plain(handshake_state *h, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(h, sizeof *h), "out_plain: state writable");
    __CPROVER_assert(SRV_OUT_STAGE + n <= sizeof h->t->tx, "out_plain: the message fits tx");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(h->t->tx + SRV_OUT_STAGE, n),
                     "out_plain: staged bytes readable");
    return out_result(h, 0);
}

int srv_out_record(handshake_state *h, const uint8_t *rec, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(h, sizeof *h), "out_record: state writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(rec, n), "out_record: record readable");
    return out_result(h, 0);
}

int srv_out_sealed(handshake_state *h, const uint8_t *pt, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(h, sizeof *h), "out_sealed: state writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "out_sealed: plaintext readable");
    return out_result(h, 1);
}

// srv_frag_flush hashes and sends what the writer holds once, and only
// while rc is CH_OK; it leaves the writer empty.
void srv_frag_flush(srv_frag *f) {
    __CPROVER_assert(__CPROVER_w_ok(f, sizeof *f), "frag_flush: writer writable");
    __CPROVER_assert(f->len <= sizeof f->buf, "frag_flush: length inside the writer");
    if (f->rc != CH_OK || f->len == 0) {
        return;
    }
    f->rc = out_result(f->h, 1);
    f->len = 0;
}

// srv_frag_bytes copies and flushes until n bytes are in or rc is not
// CH_OK, so any length the writer can hold may remain.
void srv_frag_bytes(srv_frag *f, const uint8_t *p, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(f, sizeof *f), "frag_bytes: writer writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(p, n), "frag_bytes: bytes readable");
    if (f->rc != CH_OK || n == 0) {
        return;
    }
    if ((nondet_u8() & 1) != 0) {
        f->rc = out_result(f->h, 1);
    }
    size_t len = nondet_size_t();
    __CPROVER_assume(len <= sizeof f->buf);
    f->len = len;
}

#endif
