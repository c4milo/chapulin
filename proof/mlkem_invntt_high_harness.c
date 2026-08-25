// Proves: mlk_invntt_high — the len 32..128 butterfly layers of the
// inverse NTT and its final scale pass — is memory-safe and UB-free
// with the signed-overflow check on, over coefficients ranging over
// ALL of int16. mlkem_invntt_low_harness.c proves the other half and
// states the composition argument for mlk_poly_invntt.
#include "harness.h"

#include "mlkem_poly.c"

int16_t nondet_i16(void);

// Typed, fixed-index stores: filling through a byte pointer would make
// every store a whole-object update in the SSA (see mlkem_poly_harness.c).
static void fill_poly_nondet(mlk_poly *p) {
    for (unsigned i = 0; i < 256; i++) {
        p->coeffs[i] = nondet_i16();
    }
}

int main(void) {
    mlk_poly p;

    fill_poly_nondet(&p);
    mlk_invntt_high(p.coeffs);
    return 0;
}
