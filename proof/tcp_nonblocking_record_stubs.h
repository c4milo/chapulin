// Contract stubs for the five record-layer calls both tcp-nonblocking
// drivers make: hsr_feed, hsr_check_record_end, hsr_peek_message and
// hsr_refuse_alert, which handshake_record.c's harness proves, and
// rec_open, which record.c's harness proves. proof/tcp_nonblocking_harness.c
// and proof/srv_tcp_nonblocking_harness.c include it after their helpers,
// whose nondet_int and fill_nondet it reads.
#ifndef CH_TCP_NONBLOCKING_RECORD_STUBS_H
#define CH_TCP_NONBLOCKING_RECORD_STUBS_H

#include "handshake_message.h"
#include "handshake_record.h"
#include "record.h"

// Reassembly, proven in handshake_record.c's own harness. It writes
// nothing outside cfg.buf, pt_off and pt_len, and it cannot fail: a short
// count is what tcp_nonblocking_take_record reads as a record over the limit.
size_t hsr_feed(handshake_state *h, const uint8_t *p, size_t n) {
    __CPROVER_assert(h != NULL && h->t != NULL, "feed: state valid");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(p, n), "feed: plaintext readable");
    size_t room = h->t->cfg.buf_len - h->t->pt_len;
    size_t took = n <= room ? n : room;
    h->t->pt_len += took;
    return took;
}

// The check before a key change, to the contract handshake_record.h
// states: CH_OK when no handshake byte is unread, and otherwise CH_EPROTO
// with ALERT_UNEXPECTED_MESSAGE written first.
int hsr_check_record_end(handshake_state *h) {
    __CPROVER_assert(h != NULL && h->t != NULL, "record end: state valid");
    if (h->t->pt_off != h->t->pt_len) {
        h->alert = ALERT_UNEXPECTED_MESSAGE;
        return CH_EPROTO;
    }
    return CH_OK;
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

// The refusal of an alert record, to the contract handshake_record.h
// states: a record that is not one 2-byte alert writes decode_error, an
// error alert is written to alert_received, and the answer is CH_EPROTO.
int hsr_refuse_alert(ch_tls *t, const uint8_t *pt, size_t n, uint8_t *alert) {
    __CPROVER_assert(t != NULL && alert != NULL, "refuse alert: outputs valid");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pt, n), "refuse alert: plaintext readable");
    if (n != 2) {
        *alert = ALERT_DECODE_ERROR;
        return CH_EPROTO;
    }
    if (pt[1] != ALERT_CLOSE_NOTIFY && pt[1] != ALERT_USER_CANCELED) {
        t->alert_received = pt[1];
    }
    return CH_EPROTO;
}

// Record protection, proven in record.c's harness.
// tcp_nonblocking_frame.c calls it with pt == rec, which is the
// in-place shape tcp_nonblocking.h admits, so the assertion below
// is the aliasing this caller really uses.
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

#endif
