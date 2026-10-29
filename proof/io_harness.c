// Proves: io_read_record is memory-safe and UB-free against a transport
// that returns anything at all, and a record it accepts lies wholly
// inside the caller's buffer. io_send_harness.c proves io_send_all: its
// loop beside this one took the solver past 17 minutes in one formula.
//
// The callbacks are the one part of this library somebody else writes, so
// the recv stub honours no contract: it returns an arbitrary int and
// writes only the bytes it claims, up to what it was asked for. That is
// what makes read_exact's `got <= 0 || (size_t)got > n` the thing under
// proof rather than an assumption.
#include <string.h>

#include "harness.h"

#include "io.c"

// harness.h declares size_t and u8; the transport returns an int.
int nondet_int(void);

#define IO_CAP 16

static uint8_t g_buf[IO_CAP];

static int recv_hostile(void *io, uint8_t *p, size_t n) {
    (void)io;
    int got = nondet_int();
    // A transport writes at most what it was handed room for; anything
    // beyond that is the caller's bug, not this module's.
    if (got > 0 && (size_t)got <= n) {
        fill_nondet(p, (size_t)got);
    }
    return got;
}

static ch_tls session;

int main(void) {
    session.cfg.recv = recv_hostile;
    session.cfg.buf = g_buf;
    session.cfg.buf_len = nondet_size_t();
    __CPROVER_assume(session.cfg.buf_len <= sizeof g_buf);
    session.limit_sent = nondet_u8();
    __CPROVER_assume(session.limit_sent <= 1);

    // Every caller reads into the room behind the bytes it holds, so cap
    // is at most cfg.buf_len.
    size_t cap = nondet_size_t();
    __CPROVER_assume(cap <= session.cfg.buf_len);
    uint8_t outer = 0;
    size_t record_len = 0;
    uint8_t alert = nondet_u8();
    uint8_t alert_before = alert;

    int rc = io_read_record(&session, g_buf, cap, &outer, &record_len, &alert);

    // io.h's two alerts: record_overflow with CH_EPROTO for a body over
    // rec_body_max, and with CH_ECAP for a record over all of cfg.buf once
    // this side sent its limit, and internal_error with CH_ECAP before.
    if (alert != alert_before) {
        int body_rule = rc == CH_EPROTO && alert == ALERT_RECORD_OVERFLOW;
        int over_limit = rc == CH_ECAP && alert == ALERT_RECORD_OVERFLOW && session.limit_sent;
        int no_limit = rc == CH_ECAP && alert == ALERT_INTERNAL_ERROR && !session.limit_sent;
        __CPROVER_assert(body_rule || over_limit || no_limit,
                         "io: a changed alert is one io.h names, on its result");
    }

    // An accepted record is framed inside the buffer it was read into, or
    // every caller that trusts record_len walks off the end.
    if (rc == CH_OK) {
        __CPROVER_assert(record_len >= REC_HDR, "io: an accepted record carries a header");
        __CPROVER_assert(record_len <= cap, "io: an accepted record fits the buffer");
    }
    return 0;
}
