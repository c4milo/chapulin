// Proves: the coefficient functions in mldsa_poly.h meet the contracts
// proof/mldsa_stubs.h states for them, on every input, with the
// signed-overflow check on.
//
// - mld_reduce32: every int32_t input gives a result within 6291200, so
//   under 2^23 in absolute value, that differs from the input by a
//   multiple of q.
// - mld_mul_zeta: every twiddle within (q - 1) / 2 and every int32_t
//   operand give a result under q.
// - mld_mul_reduced: every pair of int32_t operands gives a result under q.
// - mld_use_hint_coefficient: every int32_t input and either hint give a
//   value in 0..15.
//
// The mldsa_ntt and mldsa_poly harnesses prove the loops over these
// functions with each one replaced by its contract. That composition gives
// up only the values: bin/mldsa_test holds those against FIPS 204's
// formulas, every Decompose and UseHint input among them.
#include "harness.h"

#include "mldsa_poly.h"

int32_t nondet_i32(void);

int main(void) {
    int32_t a = nondet_i32();
    int32_t r = mld_reduce32(a);
    __CPROVER_assert(r <= 6291200 && r >= -6291200, "mld_reduce32: within 6291200");
    __CPROVER_assert(((int64_t)a - r) % MLD_Q == 0, "mld_reduce32: congruent mod q");

    int32_t zeta = nondet_i32();
    __CPROVER_assume(zeta <= (MLD_Q - 1) / 2 && zeta >= -(MLD_Q - 1) / 2);
    int32_t operand = nondet_i32();
    int32_t twiddled = mld_mul_zeta(zeta, operand);
    __CPROVER_assert(twiddled < MLD_Q && twiddled > -MLD_Q, "mld_mul_zeta: under q");

    int32_t x = nondet_i32();
    int32_t y = nondet_i32();
    int32_t product = mld_mul_reduced(x, y);
    __CPROVER_assert(product < MLD_Q && product > -MLD_Q, "mld_mul_reduced: under q");

    int32_t w = nondet_i32();
    uint32_t hint = nondet_u32();
    __CPROVER_assume(hint <= 1);
    uint32_t r1 = mld_use_hint_coefficient(w, hint);
    __CPROVER_assert(r1 < 16, "mld_use_hint_coefficient: a 4-bit value");
    return 0;
}
