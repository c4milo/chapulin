// Proves: p256_wide_wipe_below is memory-safe and UB-free, the call it makes
// through the volatile pointer runs wipe_frame, and wipe_frame's one wipe
// covers its array of P256_WIDE_BELOW_LEN bytes and no byte outside it:
// ct_wipe is the stub every harness links, a loop of bounds-checked stores
// (proof/ct_wipe_stub.c), and the unwinding assertion on that loop proves it
// ran exactly the array's length.
//
// CBMC reads the volatile pointer as the value it was initialized with,
// wipe_frame, as proof/ct_wipe_harness.c says of ct_wipe.c's pointer.
//
// Not proven here, and not a property of C: that the array lies where the
// frames of the call before it lay. bin/p256_equiv_test measures that on
// each compiler it runs under (test/p256_equiv_residue.h).
#include "harness.h"

#include "p256_wide_wipe.c"

int main(void) {
    p256_wide_wipe_below();
    return 0;
}
