// Proves: mlk_poly_ntt is memory-safe and UB-free with the
// signed-overflow check on, over polynomials whose coefficients range
// over ALL of int16 — wider than any caller passes, and the domain
// mlkem_harness.c's stubs assume. The functions built from
// chained Montgomery products (this transform, the two halves of its
// inverse, the base multiplication) each get their own slow-tier
// formula: SAT cost grows with the number of multiplies in one
// formula — the same reason handshake_parser and eeparse split — and merging
// these with the rest of the module was killed at 14 GB. The overflow
// verdict is the interesting one: it shows the reduction constants
// keep every intermediate product inside int32 whatever the input
// coefficients are.
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
    mlk_poly_ntt(&p);
    return 0;
}
