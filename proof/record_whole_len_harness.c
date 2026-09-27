// Proves: ch_record_whole_len (tcp_nonblocking_frame.c) reads no byte
// outside p[0..n) and answers exactly what tcp_nonblocking.h states, for
// every n up to 2^20 and every byte p holds:
//
//   - 0 while n is under REC_HDR, and while the length field names a body
//     longer than the n - REC_HDR bytes after the header;
//   - REC_HDR for a length field above 2^14 + 256, RFC 9846 §5.2's cap;
//   - REC_HDR plus the length field otherwise.
//
// So every answer is 0 or a length from REC_HDR to n, which the harness
// asserts on its own as well.
//
// p is a heap object of exactly n bytes, so a read at p[n] or before p[0]
// is a bounds failure, whatever n is, where a pointer into a larger array
// would pass a read before p[0]. The heap is the harness's, not the
// library's: CBMC gives the object n unconstrained bytes. The bound on n
// covers every branch, since the longest record the call frames is
// REC_HDR + 2^14 + 256 bytes, and the call has no loop for a larger n to
// unroll. buf.c is real, on the launch line.
#include "harness.h"

#include <stdlib.h>

#include "tcp_nonblocking_frame.c"

// The largest n the harness takes, 2^20 bytes.
#define WHOLE_LEN_N_MAX ((size_t)1 << 20)

// The largest value RFC 9846 §5.2 lets a length field hold.
#define WHOLE_LEN_BODY_MAX ((size_t)0x4000 + 256)

// What tcp_nonblocking.h says the answer is, read from p's own header.
static size_t stated_answer(const uint8_t *p, size_t n) {
    if (n < REC_HDR) {
        return 0;
    }
    size_t body_len = ((size_t)p[3] << 8) | p[4];
    if (body_len > WHOLE_LEN_BODY_MAX) {
        return REC_HDR;
    }
    return n - REC_HDR < body_len ? 0 : REC_HDR + body_len;
}

int main(void) {
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= WHOLE_LEN_N_MAX);
    uint8_t *p = malloc(n);
    __CPROVER_assume(p != NULL);

    size_t whole = ch_record_whole_len(p, n);

    __CPROVER_assert(whole == 0 || (whole >= REC_HDR && whole <= n),
                     "whole_len: the answer is 0 or a length from REC_HDR to n");
    __CPROVER_assert(whole == stated_answer(p, n),
                     "whole_len: the answer tcp_nonblocking.h states");
    free(p);
    return 0;
}
