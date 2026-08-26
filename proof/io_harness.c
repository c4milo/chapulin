// Proves: io_read_record and io_send_all are memory-safe and UB-free
// against a transport that returns anything at all, and a record it
// accepts lies wholly inside the caller's buffer.
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

static int send_hostile(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    return nondet_int();
}

int main(void) {
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.recv = recv_hostile;
    cfg.send = send_hostile;

    size_t cap = nondet_size_t();
    __CPROVER_assume(cap <= sizeof g_buf);
    uint8_t outer = 0;
    size_t record_len = 0;

    int rc = io_read_record(&cfg, g_buf, cap, &outer, &record_len);

    // An accepted record is framed inside the buffer it was read into, or
    // every caller that trusts record_len walks off the end.
    if (rc == CH_OK) {
        __CPROVER_assert(record_len >= REC_HDR, "io: an accepted record carries a header");
        __CPROVER_assert(record_len <= cap, "io: an accepted record fits the buffer");
    }

    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof g_buf);
    (void)io_send_all(&cfg, g_buf, n);
    return 0;
}
