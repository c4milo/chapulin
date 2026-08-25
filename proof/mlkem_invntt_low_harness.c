// Proves: mlk_invntt_low — the len 2..16 butterfly layers of the
// inverse NTT — is memory-safe and UB-free with the signed-overflow
// check on, over coefficients ranging over ALL of int16, wider than any
// caller passes and the domain mlkem_harness.c's stubs assume. The
// inverse NTT is split at this half exactly because one formula for
// the whole transform returns no verdict in 900 seconds; each half is
// one chained-product formula beside mlkem_ntt and mlkem_basemul.
// mlk_poly_invntt itself is the two half calls on the same coefficient
// array and adds no memory operation of its own; each half is proven
// here on any int16 coefficients, which covers the value the other
// half hands it. Includes the module .c to reach the static, as the
// unit tests do.
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
    mlk_invntt_low(p.coeffs);
    return 0;
}
