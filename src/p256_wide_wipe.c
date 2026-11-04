// The wipe of the stack a wide P-256 call used (see p256_wide_wipe.h for why it exists and
// what it covers).
#include "p256_wide_wipe.h"

#ifdef CH_CPU_RUNTIME

#include <stdint.h>

#include "ct.h"

// The frame of this function is the array. ct_wipe is compiled apart from it and takes the
// array's address, so the compiler keeps the array in memory and cannot delete the call.
static void wipe_frame(void) {
    uint8_t below[P256_WIDE_BELOW_LEN];
    ct_wipe(below, sizeof below);
}

// p256_wide_wipe_below calls wipe_frame through this pointer, for the reason ct_wipe.c calls
// memset through one: the pointer is a volatile object, so the compiler cannot tell which
// function the call runs and cannot compile it into the caller, where the array would join the
// caller's frame and lie above the frames it is there to wipe.
static void (*const volatile wipe_frame_call)(void) = wipe_frame;

void p256_wide_wipe_below(void) {
    wipe_frame_call();
}

#endif // CH_CPU_RUNTIME
