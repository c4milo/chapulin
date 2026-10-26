// Proves: mldsa_poly.c's NTT and inverse NTT are memory-safe and UB-free,
// with the signed-overflow check on, over polynomials whose coefficients
// range over all of int32_t. Every twiddle each one passes to mld_mul_zeta
// is at most (q - 1) / 2, the bound under which that product's result is
// under q. The inverse NTT's sums double their bound each layer, and this
// formula shows that eight layers of them stay inside int32_t.
//
// The coefficient functions are replaced with their contracts
// (proof/mldsa_stubs.h), so the formula holds no multiply.
// mldsa_coefficient proves the real functions meet those contracts on
// every input. Each transform gets freshly havocked coefficients, so
// neither is proved on the other's image only.
#include "harness.h"
#include "mldsa_poly.h"
#include "mldsa_stubs.h"

#include "mldsa_poly.c"

int32_t nondet_i32(void);

static void havoc_poly(mld_poly *p) {
    for (unsigned i = 0; i < MLD_N; i++) {
        p->coeffs[i] = nondet_i32();
    }
}

int main(void) {
    mld_poly p;
    havoc_poly(&p);
    mld_poly_ntt(&p);
    havoc_poly(&p);
    mld_poly_invntt_tomont(&p);
    return 0;
}
