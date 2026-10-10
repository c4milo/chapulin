// Proves: poly1305_ifma_blocks reads inside the message and the context
// and writes inside the context and its own frame, for one group and for
// two, from any context, over a message buffer of exactly n bytes. Two
// groups run the loop's body once and its last group once, every
// statement of a longer message. Its CH_ASSERT holds for those n, and every
// other check of the full set runs: bounds, pointers, shifts and signed
// overflow. ct_wipe is proof/ct_wipe_stub.c's loop over the struct of
// powers, so the proof also shows the wipe writes inside it.
//
// The harness defines POLY1305_IFMA_STUBS_ANY_PRODUCT, so each lane
// multiplication adds any value: no memory access reads a lane, and
// poly1305_ifma_sums and poly1305_ifma_product prove the operands' bound
// and the sums on the contracts in proof/poly1305_ifma_stubs.h, which
// poly1305_ifma_lanes_harness.c discharges.
#include <stdlib.h>

#define POLY1305_IFMA_STUBS_ANY_PRODUCT 1
#include "poly1305_ifma_stubs.h"

#include "poly1305_ifma.c"

int main(void) {
    size_t groups = nondet_size_t();
    __CPROVER_assume(groups == 1 || groups == 2);
    size_t n = groups * POLY1305_IFMA_GROUP;
    uint8_t *m = malloc(n);
    __CPROVER_assume(m != NULL);
    fill_nondet(m, n);

    poly1305 p;
    for (size_t i = 0; i < 5; i++) {
        p.r[i] = nondet_u32();
        p.h[i] = nondet_u32();
    }
    poly1305_ifma_blocks(&p, m, n);
    free(m);
    return 0;
}
