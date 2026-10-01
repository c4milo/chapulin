// Proves: ct_memeq and ct_wipe are memory-safe and UB-free for all inputs
// up to 64 bytes, and ct_memeq is functionally correct — it returns 1
// exactly when the buffers match (checked against a plain comparison over
// all 2^(8*2*64) input pairs at once). ct_wipe writes zero to a[0..n) and
// leaves every byte from a[n] on as it was.
//
// The ct_wipe here is proof/ct_wipe_stub.c, the byte loop every harness
// that calls ct_wipe links in place of ct_wipe.c, so this proves the
// stub's contract. proof/ct_wipe_harness.c proves the same of the body
// that ships.
#include "harness.h"

#include "ct.c"
#include "ct_wipe_stub.c"

int main(void) {
    uint8_t a[64];
    uint8_t b[64];
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof a);
    fill_nondet(a, sizeof a);
    fill_nondet(b, n);

    uint32_t eq = ct_memeq(a, b, n);
    uint32_t want = 1;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            want = 0;
        }
    }
    __CPROVER_assert(eq == want, "ct_memeq matches plain comparison");

    uint8_t before[64];
    for (size_t i = 0; i < sizeof a; i++) {
        before[i] = a[i];
    }
    ct_wipe(a, n);
    for (size_t i = 0; i < sizeof a; i++) {
        if (i < n) {
            __CPROVER_assert(a[i] == 0, "ct_wipe zeroizes");
        } else {
            __CPROVER_assert(a[i] == before[i], "ct_wipe writes nothing past n");
        }
    }
    return 0;
}
