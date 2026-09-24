// Proves: mul in x25519_wide.c, on the real 64x64->128 multiply, over any
// operands whose limbs are under 2^54, wraps no unsigned value and leaves
// limbs 0, 2, 3 and 4 under 2^51 and limb 1 under 2^51 + 2^13 -- INV-34's
// form for mul, at the tight bound the multiply contract in
// proof/x25519_wide_stubs.h cannot see. The wrap check is
// --unsigned-overflow-check on the launch line: every column sum of five
// products, every carry between columns and the fold of the top carry
// times 19 is checked there, so the 2^115 column bound and the 2^64 carry
// bound INV-34 states are what keep those checks green.
//
// One formula per call: the output distinct from both operands, as step()
// calls it. The aliasing shapes invert() and step() also use, mul(c, c, a)
// and mul(a, c, a), run in x25519_wide_tail over the contract; mul reads
// every operand limb before it writes one, so no shape changes a value this
// formula sees.
#include "harness.h"

#include "x25519_wide.c"

uint64_t nondet_u64(void);

int main(void) {
    fe a;
    fe b;
    fe o;
    for (size_t i = 0; i < 5; i++) {
        a[i] = nondet_u64() >> 10;
        b[i] = nondet_u64() >> 10;
    }
    mul(o, a, b);
    __CPROVER_assert(o[0] < ((uint64_t)1 << 51) && o[2] < ((uint64_t)1 << 51) &&
                         o[3] < ((uint64_t)1 << 51) && o[4] < ((uint64_t)1 << 51),
                     "mul leaves limbs 0, 2, 3 and 4 under 2^51");
    __CPROVER_assert(o[1] < ((uint64_t)1 << 51) + ((uint64_t)1 << 13),
                     "mul leaves limb 1 under 2^51 + 2^13");
    return 0;
}
