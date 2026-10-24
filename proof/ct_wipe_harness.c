// Proves: ct_wipe.c, the ct_wipe every build ships, is memory-safe and
// UB-free, writes zero to p[0..n) and writes no other byte, at every
// offset into a buffer of 96 bytes and for every n up to 64
// that fits. A null p with n of 0 is safe. That is the contract of
// proof/ct_wipe_stub.c, the loop every other harness that calls ct_wipe
// links in this file's place, and proof/ct_harness.c proves it of that
// loop (docs/decisions.md 144).
//
// ct_wipe stores bytes up to the first aligned address, then words, then
// the bytes after the last whole word. The word is 16 bytes here, the
// unsigned __int128 of a 64-bit target. proof/ct_wipe_u32_harness.c
// proves the same contract of the 4-byte word a 32-bit target stores.
// A nondet offset gives every count of head bytes, because the head is
// the distance from p to the next aligned address. n up to 64 then gives
// every count of head bytes, up to four words and every count of tail
// bytes. Each pass of the word loop stores the same type at the next
// address, so a larger n repeats a pass this bound already holds.
//
// The buffer is an array of CT_WIPE_SPAN bytes, and one nondet index j
// stands for every byte of it. CBMC checks that each store is inside the
// array. The assertions then hold the byte at j to zero inside p[0..n)
// and to its old value outside.
#include "harness.h"

#include "ct_wipe.c"

#ifdef __SIZEOF_INT128__
_Static_assert(sizeof(ct_wipe_word) == 16, "the 64-bit word is 16 bytes");
#else
_Static_assert(sizeof(ct_wipe_word) == 4, "the 32-bit word is 4 bytes");
#endif

#define CT_WIPE_BOUND 64
#define CT_WIPE_SPAN (CT_WIPE_BOUND + 32)

static uint8_t buf[CT_WIPE_SPAN];

int main(void) {
    size_t offset = nondet_size_t();
    size_t n = nondet_size_t();
    __CPROVER_assume(offset <= CT_WIPE_SPAN && n <= CT_WIPE_SPAN - offset && n <= CT_WIPE_BOUND);
    size_t j = nondet_size_t();
    __CPROVER_assume(j < CT_WIPE_SPAN);
    buf[j] = nondet_u8();
    uint8_t before = buf[j];

    ct_wipe(buf + offset, n);
    if (j >= offset && j - offset < n) {
        __CPROVER_assert(buf[j] == 0, "ct_wipe writes zero to p[0..n)");
    } else {
        __CPROVER_assert(buf[j] == before, "ct_wipe writes no byte outside p[0..n)");
    }

    ct_wipe(NULL, 0);
    return 0;
}
