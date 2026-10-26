// Proves: mldsa_sign_poly.c's NTT and inverse NTT are memory-safe and
// UB-free, with the signed-overflow check on, over polynomials whose
// coefficients range over all of int32_t. Every twiddle each one passes to
// mlds_mul_zeta is at most (q - 1) / 2. The inverse NTT's sums stay inside
// int32_t over its eight layers, as in mldsa_ntt.
//
// The coefficient functions are replaced with their contracts
// (proof/mldsa_sign_stubs.h), so the formula holds no multiply.
// mldsa_sign_coefficient and mldsa_sign_coefficient_ct prove the real
// functions meet those contracts on every input. Each transform gets
// freshly havocked coefficients.
#include "harness.h"
#include "mldsa_sign_poly.h"
#include "mldsa_sign_stubs.h"

#include "mldsa_sign_poly.c"

int32_t nondet_i32(void);

static void havoc_poly(mld_poly *p) {
    for (unsigned i = 0; i < MLD_N; i++) {
        p->coeffs[i] = nondet_i32();
    }
}

int main(void) {
    mld_poly p;
    havoc_poly(&p);
    mlds_poly_ntt(&p);
    havoc_poly(&p);
    mlds_poly_invntt_tomont(&p);
    return 0;
}
