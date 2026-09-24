// Proves: the real ct_mul128 meets the contract proof/x25519_wide_stubs.h
// replaces it with in x25519_wide_step, x25519_wide_tail and
// x25519_wide_invert. For every first operand under 2^55 and every second
// operand under 2^60, the 128-bit product is under 2^115.
//
// This is a bound, not an equality: docs/proofs.md says why a proof that
// needs only a bound should ask only for it. The operands are bit structure,
// shifts of unconstrained values, for the reason that document gives too.
// The product is ct.h's (ct_u128)a * b, the one expression every product in
// x25519_wide.c goes through.
#include "harness.h"

#include "ct.h"

uint64_t nondet_u64(void);

int main(void) {
    uint64_t a = nondet_u64() >> 9;
    uint64_t b = nondet_u64() >> 4;
    ct_u128 product = ct_mul128(a, b);
    __CPROVER_assert(product >> 115 == 0, "a product inside the contract's domain is under 2^115");
    return 0;
}
