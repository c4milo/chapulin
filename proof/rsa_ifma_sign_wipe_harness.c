// Proves: rsa_ifma_sign_wipe_below is memory-safe and UB-free, the call it
// makes through the volatile pointer runs wipe_frame, and wipe_frame's one
// wipe covers its array of RSA_IFMA_SIGN_BELOW_LEN bytes and no byte
// outside it: ct_wipe is the stub every harness links, a loop of
// bounds-checked stores (proof/ct_wipe_stub.c), and the unwinding assertion
// on that loop proves it ran exactly the array's length. The
// rsa_ifma_sign_wipe_webpki variant runs the 512-byte bound's array.
//
// CBMC reads the volatile pointer as the value it was initialized with,
// wipe_frame, as proof/ct_wipe_harness.c says of ct_wipe.c's pointer.
//
// Not proven here, and not a property of C: that the array lies where the
// frames of the calls before it lay. bin/rsa_ifma_sign_residue_test
// measures that on each compiler it runs under, as
// proof/p256_wide_wipe_harness.c says of P-256's wipe.
#include "harness.h"

#include "rsa_ifma_sign.c"

int main(void) {
    rsa_ifma_sign_wipe_below();
    return 0;
}
