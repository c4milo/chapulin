// Proves, for p256_point_mul, one round of its ladder at a time:
//
//   memory safety and absence of UB in ladder_round over three
//   unconstrained points, an unconstrained scalar and any i in [0, 255],
//   on the shipped round rather than a copy of it. The index and the
//   shift the round reads the scalar with are the one memory access that
//   moves with the loop counter, and this proves them in bounds for
//   every i rather than by argument;
//
//   that the mask the round builds from the bit is 0 or all ones, which
//   proof/p256_field_stubs.h asserts at every cswap. A bit that was never
//   widened, or a mask written as `0 - bit`, fails there. That mask is
//   the whole constant-time claim of the ladder: it is what makes the
//   round's additions unconditional and its result conditional.
//
// Why one round. The ladder unrolled its 256 rounds over the field stubs
// returned no verdict in 42 minutes. proof/x25519_step_harness.c makes
// the same split for the same reason: prove step() once, and let the
// loop in ladder() carry it. The loop here is `for i from 255 down to
// 0`, and it calls nothing but this round.
#include "harness.h"

#include "p256_field_stubs.h"

#include "p256_point.c"

static void point_nondet(p256_point *p) {
    for (size_t j = 0; j < P256_FE_LIMBS; j++) {
        p->x.limb[j] = nondet_u32();
        p->y.limb[j] = nondet_u32();
        p->z.limb[j] = nondet_u32();
    }
}

int main(void) {
    p256_scalar k;
    p256_point r0;
    p256_point r1;
    p256_point sum;

    for (size_t j = 0; j < P256_SCALAR_LIMBS; j++) {
        k.limb[j] = nondet_u32();
    }
    point_nondet(&r0);
    point_nondet(&r1);
    point_nondet(&sum);
    int i = (int)nondet_i64();
    __CPROVER_assume(i >= 0 && i < P256_SCALAR_LIMBS * 32);
    ladder_round(&r0, &r1, &sum, &k, i);
    return 0;
}
