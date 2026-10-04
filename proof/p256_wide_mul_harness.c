// Proves, for p256_wide_mul.c, the whole of p256_wide_mul and
// p256_wide_base_mul over an unconstrained scalar and an unconstrained
// point, all 256 rounds of the shipped loop in one formula:
//
//   memory safety and absence of UB. The index and the shift each round
//   reads the scalar with are the one access that moves with the loop
//   counter, and they are proven in bounds at every trip, on the shipped
//   loop;
//
//   that the mask each round builds from its bit is 0 or all ones, which
//   proof/p256_wide_field_stubs.h asserts at every exchange. A bit that was
//   never widened to a mask fails there. The mask is the ladder's whole
//   constant-time claim: it makes the round's two additions unconditional
//   and its result conditional;
//
//   that the three wipes at the end stay inside the points they name
//   (ct_wipe's stub).
//
// The point formulas are the stubs in proof/p256_wide_point_stubs.h, and the
// field's exchange is the stub in proof/p256_wide_field_stubs.h, so nothing
// here depends on a coordinate. p256_wide_mask is the real one.
// p256_point_infinity and p256_point_generator come from
// proof/p256_point_stubs.h, as placeholders: the stubs read no coordinate.
//
// Not proven here: that 256 rounds compute k times the point.
// bin/p256_equiv_test holds both entries to p256_point.c's on edge and
// random scalars.
#include "p256_point_stubs.h"
#include "p256_wide_field_stubs.h"
#include "p256_wide_point_stubs.h"

#include "p256_wide_mul.c"

int main(void) {
    p256_scalar k;
    p256_point p;
    p256_point o;

    for (size_t i = 0; i < P256_SCALAR_LIMBS; i++) {
        k.limb[i] = nondet_u32();
    }
    for (size_t i = 0; i < P256_FE_LIMBS; i++) {
        p.x.limb[i] = nondet_u32();
        p.y.limb[i] = nondet_u32();
        p.z.limb[i] = nondet_u32();
    }
    p256_wide_mul(&o, &k, &p);

    for (size_t i = 0; i < P256_SCALAR_LIMBS; i++) {
        k.limb[i] = nondet_u32();
    }
    p256_wide_base_mul(&o, &k);
    return 0;
}
