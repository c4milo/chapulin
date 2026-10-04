// Proves: the real ct_mul128 meets the contract proof/rsa_mont64_stubs.h
// replaces it with. For every pair of 64-bit operands, the 128-bit
// product is at or below (2^64 - 1)^2.
//
// That bound is what rsa_mont64.c's sums rest on: a product, a limb of
// the running sum and a carry add up to at most 2^128 - 1, so no sum
// wraps. It is a bound, not an equality, for the reason docs/proofs.md
// gives. The product is ct.h's (ct_u128)a * b, the one expression every
// product in rsa_mont64.c goes through.
#include "harness.h"

#include "ct.h"

uint64_t nondet_u64(void);

int main(void) {
    uint64_t a = nondet_u64();
    uint64_t b = nondet_u64();
    ct_u128 product = ct_mul128(a, b);
    ct_u128 max = (((ct_u128)(UINT64_MAX - 1)) << 64) | 1;
    __CPROVER_assert(product <= max, "a product of two limbs is at or below (2^64 - 1)^2");
    return 0;
}
