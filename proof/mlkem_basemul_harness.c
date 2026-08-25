// Proves: mlk_poly_basemul is memory-safe and UB-free with the
// signed-overflow check on, over two polynomials whose coefficients
// range over ALL of int16 — wider than any caller passes, and the
// domain mlkem_harness.c's stubs assume. One of the three
// chained-product formulas; mlkem_ntt_harness.c states the split.
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
    mlk_poly a;
    mlk_poly b;
    mlk_poly r;

    fill_poly_nondet(&a);
    fill_poly_nondet(&b);
    mlk_poly_basemul(&r, &a, &b);
    return 0;
}
