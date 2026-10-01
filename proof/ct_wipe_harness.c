// Proves: ct_wipe.c, the ct_wipe every build ships, which calls memset
// through a volatile function pointer, is memory-safe and UB-free, writes
// zero to p[0..n) and writes no other byte, for a buffer of every size
// CBMC's pointer encoding holds, at every offset and for every n that
// fits, and makes no call when n is 0, so a null p with nothing to wipe is
// safe. That is the contract of proof/ct_wipe_stub.c, the loop every other
// harness that calls ct_wipe links in this file's place, and
// proof/ct_harness.c proves it of that loop.
//
// The buffer is a heap object of nondet size, which CBMC reasons about as
// an array of unbounded length rather than byte by byte, and one nondet
// index stands for every byte of it. memset is CBMC's model of it: a check
// that p[0..n) is writable, then an array write of n copies of the value.
// CBMC reads the volatile pointer as the value it was initialized with,
// memset.
#include "harness.h"

#include <stdlib.h>

#include "ct_wipe.c"

int main(void) {
    size_t cap = nondet_size_t();
    __CPROVER_assume(cap <= __CPROVER_max_malloc_size);
    uint8_t *buf = malloc(cap);
    __CPROVER_assume(buf != NULL);
    size_t offset = nondet_size_t();
    size_t n = nondet_size_t();
    __CPROVER_assume(offset <= cap && n <= cap - offset);
    size_t j = nondet_size_t();
    __CPROVER_assume(j < cap);
    buf[j] = nondet_u8();
    uint8_t before = buf[j];

    ct_wipe(buf + offset, n);
    if (j >= offset && j - offset < n) {
        __CPROVER_assert(buf[j] == 0, "ct_wipe writes zero to p[0..n)");
    } else {
        __CPROVER_assert(buf[j] == before, "ct_wipe writes no byte outside p[0..n)");
    }

    ct_wipe(NULL, 0);
    free(buf);
    return 0;
}
