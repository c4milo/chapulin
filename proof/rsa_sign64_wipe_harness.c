// Proves: rsa_sign64_wipe_below is memory-safe and UB-free, the call it
// makes through the volatile pointer runs wipe_frame, and wipe_frame's one
// wipe covers its array of RSA_SIGN64_BELOW_LEN bytes and no byte outside
// it: ct_wipe is the stub every harness links, a loop of bounds-checked
// stores (proof/ct_wipe_stub.c), and the unwinding assertion on that loop
// proves it ran exactly the array's length.
//
// CBMC reads the volatile pointer as the value it was initialized with,
// wipe_frame, as proof/p256_wide_wipe_harness.c says of P-256's wipe.
//
// Not proven here, and not a property of C: that the array lies where the
// frames of the call before it lay. bin/rsa_sign_equiv_test requires the
// stack below each wrapped call equal under two secrets, on each compiler
// it runs under (test/rsa_sign_equiv_differential.h).
#include "harness.h"

#include "rsa_sign64_wipe.c"

int main(void) {
    rsa_sign64_wipe_below();
    return 0;
}
