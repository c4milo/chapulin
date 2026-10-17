// Proves: io_send_all is memory-safe and UB-free against a send that
// returns anything at all; each send call starts at the first byte not
// yet moved and is handed every byte left; and a CH_OK means the send
// moved all n bytes (cfg.h's send rule).
//
// The callbacks are the one part of this library somebody else writes, so
// the send stub honours no contract: it returns an arbitrary int. That is
// what makes io_send_all's `sent <= 0 || (size_t)sent > n` the thing under
// proof rather than an assumption. io_harness.c proves io_read_record
// apart, because the two loops in one formula kept the solver past 17
// minutes.
#include <string.h>

#include "harness.h"

#include "io.c"

// harness.h declares size_t and u8; the transport returns an int.
int nondet_int(void);

// The record io_send_all is handed, at most this many bytes. A send that
// moves one byte a call runs the loop once per byte, which sets the unwind.
#define IO_SEND_CAP 16

static uint8_t g_buf[IO_SEND_CAP];
static size_t g_send_len; // the n io_send_all was handed
static size_t g_sent;     // the bytes the stub has claimed it moved

static int send_hostile(void *io, const uint8_t *p, size_t n) {
    (void)io;
    __CPROVER_assert(g_sent < g_send_len, "io_send: a send call comes only while bytes are left");
    __CPROVER_assert(p == g_buf + g_sent,
                     "io_send: a send call starts at the first byte not yet moved");
    __CPROVER_assert(n == g_send_len - g_sent, "io_send: a send call is handed every byte left");
    int sent = nondet_int();
    if (sent > 0 && (size_t)sent <= n) {
        g_sent += (size_t)sent;
    }
    return sent;
}

int main(void) {
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.send = send_hostile;

    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof g_buf);
    g_send_len = n;
    g_sent = 0;
    int rc = io_send_all(&cfg, g_buf, n);
    __CPROVER_assert(rc == CH_OK || rc == CH_EIO, "io_send: the verdict is CH_OK or CH_EIO");
    if (rc == CH_OK) {
        __CPROVER_assert(g_sent == n, "io_send: an accepted send moved all n bytes");
    }
    return 0;
}
