// Proves: the coefficient functions of ML-DSA-87 signing, in
// mldsa_sign_poly.h and mldsa_sign_pack.h, meet the contracts that
// proof/mldsa_sign_stubs.h states for them and the values FIPS 204 gives,
// on every input, with the signed-overflow check on.
//
// - mlds_reduce32: within 6291200 and congruent to the input mod q.
// - mlds_mul_zeta: under q for a twiddle within (q - 1) / 2 and every
//   operand. mlds_mul_reduced: under q for every pair of operands.
// - mlds_freeze: in [0, q). mlds_center: in [-(q - 1) / 2, (q - 1) / 2].
//   Each congruent to the input mod q.
// - mlds_decompose, for r in [0, q): r1 in 0..15, r0 in [-gamma2, gamma2],
//   and r = r1 * 2 * gamma2 + r0 mod q (FIPS 204 Algorithm 36).
// - mlds_power2round, for r in [0, q): r = t1 * 2^13 + t0 with t0 in
//   (-2^12, 2^12] (Algorithm 35).
// - mlds_at_least: 1 exactly when |a| >= bound, in the domain its header
//   states. mlds_mask_eq and mlds_select: the masks they state.
//
// run.sh compiles this formula with CH_NATIVE_WIDEMUL, so ct_widemul_s is
// one product. ctwidemul proves the decomposition computes the same
// product, and bin/mldsa_signer_test_ct_widemul runs the signer on it.
#include "harness.h"

#include "mldsa_sign_pack.h"
#include "mldsa_sign_poly.h"

int32_t nondet_i32(void);

static void coefficients(void) {
    int32_t a = nondet_i32();
    int32_t r = mlds_reduce32(a);
    __CPROVER_assert(r <= 6291200 && r >= -6291200, "mlds_reduce32: within 6291200");
    __CPROVER_assert(((int64_t)a - r) % MLD_Q == 0, "mlds_reduce32: congruent mod q");

    int32_t zeta = nondet_i32();
    __CPROVER_assume(zeta <= (MLD_Q - 1) / 2 && zeta >= -(MLD_Q - 1) / 2);
    int32_t twiddled = mlds_mul_zeta(zeta, nondet_i32());
    __CPROVER_assert(twiddled < MLD_Q && twiddled > -MLD_Q, "mlds_mul_zeta: under q");

    int32_t product = mlds_mul_reduced(nondet_i32(), nondet_i32());
    __CPROVER_assert(product < MLD_Q && product > -MLD_Q, "mlds_mul_reduced: under q");

    int32_t b = nondet_i32();
    int32_t frozen = mlds_freeze(b);
    __CPROVER_assert(frozen >= 0 && frozen < MLD_Q, "mlds_freeze: in [0, q)");
    __CPROVER_assert(((int64_t)b - frozen) % MLD_Q == 0, "mlds_freeze: congruent mod q");
    int32_t c = nondet_i32();
    int32_t centered = mlds_center(c);
    __CPROVER_assert(centered >= -(MLD_Q - 1) / 2 && centered <= (MLD_Q - 1) / 2,
                     "mlds_center: in [-(q - 1) / 2, (q - 1) / 2]");
    __CPROVER_assert(((int64_t)c - centered) % MLD_Q == 0, "mlds_center: congruent mod q");
}

static void roundings(void) {
    int32_t r = nondet_i32();
    __CPROVER_assume(r >= 0 && r < MLD_Q);
    int32_t r0 = 0;
    int32_t r1 = mlds_decompose(r, &r0);
    __CPROVER_assert(r1 >= 0 && r1 <= 15, "mlds_decompose: r1 in 0..15");
    __CPROVER_assert(r0 >= -MLD_GAMMA2 && r0 <= MLD_GAMMA2, "mlds_decompose: r0 within gamma2");
    __CPROVER_assert(((int64_t)r1 * 2 * MLD_GAMMA2 + r0 - r) % MLD_Q == 0,
                     "mlds_decompose: r = r1 * 2 * gamma2 + r0 mod q");

    int32_t t = nondet_i32();
    __CPROVER_assume(t >= 0 && t < MLD_Q);
    int32_t t0 = 0;
    int32_t t1 = mlds_power2round(t, &t0);
    __CPROVER_assert(t0 > -(1 << 12) && t0 <= 1 << 12, "mlds_power2round: t0 in (-2^12, 2^12]");
    __CPROVER_assert(t1 * (1 << MLD_D) + t0 == t, "mlds_power2round: t = t1 * 2^13 + t0");
    __CPROVER_assert(t1 >= 0 && t1 < 1024, "mlds_power2round: t1 fits 10 bits");
}

static void masks(void) {
    int32_t a = nondet_i32();
    int32_t bound = nondet_i32();
    __CPROVER_assume(bound >= 1 && bound <= (1 << 30));
    __CPROVER_assume(a < (1 << 30) && a > -(1 << 30));
    uint32_t over = mlds_at_least(a, bound);
    int32_t magnitude = a < 0 ? -a : a;
    __CPROVER_assert(over == (magnitude >= bound ? 1U : 0U), "mlds_at_least: |a| >= bound");

    uint32_t x = nondet_u32();
    uint32_t y = nondet_u32();
    uint32_t m = mlds_mask_eq(x, y);
    __CPROVER_assert(m == (x == y ? 0xffffffffU : 0U), "mlds_mask_eq: all ones exactly on a == b");
    __CPROVER_assert(mlds_select(0xffffffffU, x, y) == y, "mlds_select: takes b under all ones");
    __CPROVER_assert(mlds_select(0, x, y) == x, "mlds_select: takes a under 0");
}

int main(void) {
    coefficients();
    roundings();
    masks();
    return 0;
}
