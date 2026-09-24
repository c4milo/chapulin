// Proves: sqr in x25519_wide.c, on the real 64x64->128 multiply, over any
// operand whose limbs are under 2^54, wraps no unsigned value and leaves
// limbs 0, 2, 3 and 4 under 2^51 and limb 1 under 2^51 + 2^13 -- the
// counterpart of x25519_wide_mul_harness.c for the squaring, whose doubled
// and 38-times operands are the widest the field hands the multiply. The
// wrap check is --unsigned-overflow-check on the launch line, as there.
//
// It runs in place, sqr(a, a), the shape sqr_times() and invert() use; sqr
// reads every limb before it writes one, so the distinct-output shape step()
// uses computes the same values.
#include "harness.h"

#include "x25519_wide.c"

uint64_t nondet_u64(void);

int main(void) {
    fe a;
    for (size_t i = 0; i < 5; i++) {
        a[i] = nondet_u64() >> 10;
    }
    sqr(a, a);
    __CPROVER_assert(a[0] < ((uint64_t)1 << 51) && a[2] < ((uint64_t)1 << 51) &&
                         a[3] < ((uint64_t)1 << 51) && a[4] < ((uint64_t)1 << 51),
                     "sqr leaves limbs 0, 2, 3 and 4 under 2^51");
    __CPROVER_assert(a[1] < ((uint64_t)1 << 51) + ((uint64_t)1 << 13),
                     "sqr leaves limb 1 under 2^51 + 2^13");
    return 0;
}
