// Proves, for p256_wide_limb.h's p256_wide_sqr_product, on the real 64x64->128 multiply:
//
//   it wraps no unsigned value, over any four limbs. Its sums of a high half and a carry fit
//   64 bits because a high half is at most 2^64 - 2. Its last line adds the top bit of the
//   doubled sum, the high half of a3^2 and a carry, and that sum fits 64 bits only because
//   the square is below 2^512. The check is --unsigned-overflow-check on the launch line,
//   which makes that sum a property. This is the contract proof/p256_wide_stubs.h replaces
//   the square with: any eight limbs, and no wrap.
//
// The carry steps are the builtins, the form clang compiles. p256_wide_row_harness.c holds
// that form and the 128-bit sums to one reference, so what this proves over one form holds
// over the other.
//
// Not proven here: that the eight limbs are the square. Equality of two multipliers is the
// SAT instance docs/proofs.md says does not converge, so the square's value rests on
// bin/p256_equiv_test, which holds p256_wide_fe_sqr to p256_fe_sqr and the inverses to
// p256_fe_inv and p256_scalar_inverse, and on the vectors.
#include "harness.h"

#ifndef P256_WIDE_CARRY
#define P256_WIDE_CARRY P256_WIDE_CARRY_BUILTIN
#endif
#include "p256_wide_limb.h"

uint64_t nondet_u64(void);

int main(void) {
    uint64_t t0;
    uint64_t t1;
    uint64_t t2;
    uint64_t t3;
    uint64_t t4;
    uint64_t t5;
    uint64_t t6;
    uint64_t t7;
    p256_wide_sqr_product(&t0, &t1, &t2, &t3, &t4, &t5, &t6, &t7, nondet_u64(), nondet_u64(),
                          nondet_u64(), nondet_u64());
    return 0;
}
