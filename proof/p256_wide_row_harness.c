// Proves, for p256_wide_limb.h's four steps, on the real 64x64->128 multiply:
//
//   p256_wide_mul_row wraps no unsigned value, over any limbs at all. Its
//   last line adds two carries to the high half of the top product, and that
//   sum fits 64 bits only because the whole row, x times four limbs plus four
//   limbs, is below 2^320. The check is --unsigned-overflow-check on the
//   launch line, which makes that sum a property. This is the contract
//   proof/p256_wide_stubs.h replaces the row with: any four limbs and any
//   limb above them, and no wrap.
//
//   p256_wide_add_carry and p256_wide_sub_borrow against a 128-bit
//   reference, for any two limbs and either carry: the limb they return, and
//   a carry or borrow out that is 0 or 1 and the reference's.
//
//   p256_wide_mask gives all ones for 1 and zero for 0.
//
// Not proven here: that the five limbs a row leaves are x times b plus the
// four it was handed. Equality of two multipliers is the SAT instance
// docs/proofs.md says does not converge, so the product's value rests on
// bin/p256_equiv_test and the vectors, as p256_field.c's does on its own.
#include "harness.h"

#include "p256_wide_limb.h"

uint64_t nondet_u64(void);

int main(void) {
    uint64_t t0 = nondet_u64();
    uint64_t t1 = nondet_u64();
    uint64_t t2 = nondet_u64();
    uint64_t t3 = nondet_u64();
    uint64_t above = p256_wide_mul_row(&t0, &t1, &t2, &t3, nondet_u64(), nondet_u64(), nondet_u64(),
                                       nondet_u64(), nondet_u64());
    (void)above;

    uint64_t a = nondet_u64();
    uint64_t b = nondet_u64();
    uint64_t carry_in = nondet_u64();
    __CPROVER_assume(carry_in <= 1);
    uint64_t carry = carry_in;
    uint64_t sum = p256_wide_add_carry(&carry, a, b);
    ct_u128 wide_sum = (ct_u128)a + b + carry_in;
    __CPROVER_assert(sum == (uint64_t)wide_sum, "add_carry: the low 64 bits of a + b + carry");
    __CPROVER_assert(carry == (uint64_t)(wide_sum >> 64), "add_carry: the carry out, 0 or 1");

    uint64_t borrow = carry_in;
    uint64_t difference = p256_wide_sub_borrow(&borrow, a, b);
    // a - b - borrow, with 2^64 lent to it so that the reference never goes
    // below zero: bit 64 of the result is clear exactly when it borrowed.
    ct_u128 wide_difference = ((ct_u128)1 << 64) + a - b - carry_in;
    __CPROVER_assert(difference == (uint64_t)wide_difference,
                     "sub_borrow: the low 64 bits of a - b - borrow");
    __CPROVER_assert(borrow == 1 - (uint64_t)(wide_difference >> 64),
                     "sub_borrow: the borrow out, 0 or 1");

    __CPROVER_assert(p256_wide_mask(0) == 0, "mask: zero for 0");
    __CPROVER_assert(p256_wide_mask(1) == UINT64_MAX, "mask: all ones for 1");
    return 0;
}
