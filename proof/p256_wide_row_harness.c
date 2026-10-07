// Proves, for p256_wide_word.h's four steps, on the real 64x64->128 multiply:
//
//   p256_wide_mul_row wraps no unsigned value, over any words at all. Its
//   last line adds two carries to the high half of the top product, and that
//   sum fits 64 bits only because the whole row, x times four words plus four
//   words, is below 2^320. The check is --unsigned-overflow-check on the
//   launch line, which makes that sum a property. This is the contract
//   proof/p256_wide_stubs.h replaces the row with: any four words and any
//   word above them, and no wrap.
//
//   p256_wide_add_carry and p256_wide_sub_borrow against a 128-bit
//   reference, for any two words and either carry: the word they return, and
//   a carry or borrow out that is 0 or 1 and the reference's.
//
//   p256_wide_mask gives all ones for 1 and zero for 0.
//
// The two carry steps have three forms, and P256_WIDE_CARRY names the one a
// build compiles (p256_wide_word.h). This harness reads the builtins, the
// form clang compiles, and p256_wide_row_sum_harness.c includes it to read
// the 128-bit sums, the form gcc compiles outside x86-64. The assertions
// below hold each form to the same 128-bit reference, so the two forms
// return the same word and the same carry for every operand, and what a
// harness proves over one form holds over the other. The third form,
// gcc's for x86-64, is two intrinsics. CBMC reads none, so that form rests
// on bin/p256_equiv_test and the vectors under gcc.
//
// Not proven here: that the five words a row leaves are x times b plus the
// four it was handed. Equality of two multipliers is the SAT instance
// docs/proofs.md says does not converge, so the product's value rests on
// bin/p256_equiv_test and the vectors, as p256_field.c's does on its own.
#include "harness.h"

#ifndef P256_WIDE_CARRY
#define P256_WIDE_CARRY P256_WIDE_CARRY_BUILTIN
#endif
#include "p256_wide_word.h"

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
