// The ct_wipe every harness that calls it links in place of ct_wipe.c.
//
// ct_wipe.c calls memset through a volatile function pointer
// (docs/decisions.md 91). This is the loop ct_wipe was before that: one
// store per byte through a volatile pointer. Its contract is the shipped
// body's: it writes zero to p[0..n) and no other byte, and every store is
// a bounds-checked write to p[0..n), so a harness that links it also
// proves each wipe writes inside its buffer. proof/ct_harness.c proves
// the contract of this loop, and proof/ct_wipe_harness.c proves it of
// ct_wipe.c over CBMC's model of memset.
//
// The harnesses were measured with this loop, and the unwind bounds in
// proof/run.sh that name ct_wipe.0 count its iterations, so linking it
// keeps each formula the one it was. What the composition gives up is the
// call through the pointer: no harness but ct_wipe reads ct_wipe.c.
#include "ct.h"

void ct_wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    for (size_t i = 0; i < n; i++) {
        v[i] = 0;
    }
}
