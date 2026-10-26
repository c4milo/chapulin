// Proves: the products in mldsa_sign_poly.c are memory-safe and UB-free
// with the signed-overflow check on, over coefficients from all of
// int32_t, and the two that end in a reduction return what they state:
// mlds_poly_product's coefficients lie in [-(q - 1) / 2, (q - 1) / 2] and
// mlds_poly_invntt_freeze's in [0, q). mldsa_sign_ntt proves the
// transforms, and the stubs' contracts stand in for the coefficient
// functions (proof/mldsa_sign_stubs.h).
//
// The two transforms the products call run here as well, over the same
// contracts. The harness calls each product with the output apart from
// its inputs or aliased to one, the shapes mldsa_sign_round.c calls:
// pointwise_acc(row, entry, v), product(p, c, s) with p apart from both,
// and pointwise(r, a, r).
#include "harness.h"
#include "mldsa_sign_poly.h"
#include "mldsa_sign_stubs.h"

int32_t nondet_i32(void);

static void havoc_poly(mld_poly *p) {
    for (unsigned i = 0; i < MLD_N; i++) {
        p->coeffs[i] = nondet_i32();
    }
}

#include "mldsa_sign_poly.c"

int main(void) {
    mld_poly a;
    mld_poly b;
    mld_poly r;
    havoc_poly(&a);
    havoc_poly(&b);
    mlds_poly_pointwise(&r, &a, &b);
    havoc_poly(&a);
    havoc_poly(&b);
    mlds_poly_pointwise(&b, &a, &b);
    havoc_poly(&a);
    havoc_poly(&b);
    havoc_poly(&r);
    mlds_poly_pointwise_acc(&r, &a, &b);
    havoc_poly(&a);
    havoc_poly(&b);
    mlds_poly_product(&r, &a, &b);
    unsigned n = nondet_u32() % MLD_N;
    __CPROVER_assert(r.coeffs[n] >= -(MLD_Q - 1) / 2 && r.coeffs[n] <= (MLD_Q - 1) / 2,
                     "mlds_poly_product: each coefficient centered");
    havoc_poly(&r);
    mlds_poly_invntt_freeze(&r);
    __CPROVER_assert(r.coeffs[n] >= 0 && r.coeffs[n] < MLD_Q,
                     "mlds_poly_invntt_freeze: each coefficient in [0, q)");
    return 0;
}
