// Proves: ct_memeq and ct_wipe are memory-safe and UB-free for all inputs
// up to 64 bytes, and ct_memeq is functionally correct — it returns 1
// exactly when the buffers match (checked against a plain comparison over
// all 2^(8*2*64) input pairs at once).
#include "harness.h"

#include "ct.c"

int main(void) {
    uint8_t a[64];
    uint8_t b[64];
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof a);
    fill_nondet(a, n);
    fill_nondet(b, n);

    uint32_t eq = ct_memeq(a, b, n);
    uint32_t want = 1;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) {
            want = 0;
        }
    }
    __CPROVER_assert(eq == want, "ct_memeq matches plain comparison");

    ct_wipe(a, n);
    for (size_t i = 0; i < n; i++) {
        __CPROVER_assert(a[i] == 0, "ct_wipe zeroizes");
    }
    return 0;
}
