// Proves, for p256_point.c's addition and its affine reader:
//
//   memory safety and absence of UB in p256_point_add over
//   unconstrained coordinates, in every aliasing shape its callers use
//   -- separate output, output over the first input, output over the
//   second input, and both inputs the same object, which is the
//   doubling the ladder performs. The last shape is the one a formula
//   that wrote a coordinate before its last read would get wrong;
//
//   memory safety and absence of UB in p256_point_affine_x, and that
//   its answer is a mask rather than a flag, which is what lets a
//   caller combine it with mask arithmetic;
//
//   that every mask p256_point_add hands p256_fe_cmov is 0 or all ones,
//   over the stub in proof/p256_field_stubs.h.
//
// Layered proof, in the shape hkdf_harness.c uses: the field arithmetic
// is stubbed and the real bodies are proven in
// proof/p256_field_harness.c. Nothing here depends on a field value,
// which is why the formula converges: one p256_point_add runs 14
// Montgomery products, and a proof that unrolled them would return no
// verdict.
//
// The ladder is not here. proof/p256_point_ladder_harness.c drives it,
// with the same stubs stripped to their masks, because 256 rounds times
// two additions times the stubs' own assertions is a formula this one's
// budget cannot hold.
//
// Not proven here or there: that the 43 steps of p256_point_add compute
// the group law. That is an algebraic claim over the field, not a
// memory claim. It is checked by running the same 43 steps in Python
// against an affine reference -- on 384 cases, including a point with
// itself, a point with its negative and either operand at infinity --
// in test/gen_p256_sign_vectors.py, and by the whole signatures in
// test/p256_sign_test.c.
#include "harness.h"

#include "p256_field_stubs.h"

#include "p256_point.c"

static void point_nondet(p256_point *p) {
    for (size_t i = 0; i < P256_FE_LIMBS; i++) {
        p->x.limb[i] = nondet_u32();
        p->y.limb[i] = nondet_u32();
        p->z.limb[i] = nondet_u32();
    }
}

// Every aliasing shape a caller uses, over unconstrained coordinates.
static void prove_add_aliasing(void) {
    p256_point a;
    p256_point b;
    p256_point o;

    point_nondet(&a);
    point_nondet(&b);
    p256_point_add(&o, &a, &b);

    point_nondet(&a);
    point_nondet(&b);
    p256_point_add(&a, &a, &b); // o == a

    point_nondet(&a);
    point_nondet(&b);
    p256_point_add(&b, &a, &b); // o == b

    point_nondet(&a);
    p256_point_add(&a, &a, &a); // o == a == b, the ladder's doubling
}

static void prove_affine_x(void) {
    p256_point a;
    uint8_t out[P256_FE_LEN];

    point_nondet(&a);
    fill_nondet(out, sizeof out);
    uint32_t finite = p256_point_affine_x(out, &a);
    __CPROVER_assert(finite == 0 || finite == UINT32_MAX,
                     "p256_point_affine_x: the answer is a mask, not a flag");
}

int main(void) {
    prove_add_aliasing();
    prove_affine_x();
    return 0;
}
