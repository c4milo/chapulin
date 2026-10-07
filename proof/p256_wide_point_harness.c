// Proves, for p256_wide_point.c, over the wide field's stubs
// (proof/p256_wide_field_stubs.h):
//
//   memory safety and absence of UB in p256_wide_point_add over
//   unconstrained coordinates, in every aliasing shape its callers use:
//   separate output, output over the first input, output over the second,
//   and both inputs and the output one object, and the shape a formula that wrote a coordinate
//   before its last read would get wrong;
//
//   the same in p256_wide_point_add_affine, in both shapes the base
//   multiplication uses: separate output, and output over the projective
//   input;
//
//   the same in p256_wide_point_double, separate output and output over
//   the input, which is how a multiplication doubles between windows;
//
//   memory safety in p256_wide_point_from_bytes over any 65 bytes, and that
//   its answer is 0 or UINT32_MAX, the mask p256_point.h promises, whichever
//   64-bit mask the field gave it: the low half of a 64-bit mask is a 32-bit
//   one;
//
//   memory safety in p256_wide_point_affine with and without a y output,
//   that its answer is 0 or UINT32_MAX, and that the three wipes it makes
//   stay inside the objects they name (ct_wipe's stub);
//
//   memory safety in the two copies between a p256_point and a
//   p256_wide_point.
//
// Layered proof, in the shape proof/p256_point_harness.c uses: the field is
// stubbed, so nothing here depends on a field value, and the real field
// bodies are proven in the three p256_wide_field harnesses.
//
// Not proven here: that the three formulas compute the group law.
// bin/p256_equiv_test holds the two additions to p256_point_add's
// coordinates, word for word, on random and structured operands, and the
// doubling to the point p256_point_add gives for a point with itself. That
// routine's steps are checked against an affine reference in
// test/gen_p256_sign_vectors.py. The doubling's steps are proven in Lean
// instead: spec/lean/Spec/P256WidePoint.lean proves that they double
// every point of the curve, and bin/diff_p256_wide holds this file's
// doubling to them, coordinate for coordinate.
#include "p256_wide_field_stubs.h"

#include "p256_wide_point.c"

static void wide_point_nondet(p256_wide_point *p) {
    for (size_t i = 0; i < P256_WIDE_FE_WORDS; i++) {
        p->x.word[i] = nondet_u64();
        p->y.word[i] = nondet_u64();
        p->z.word[i] = nondet_u64();
    }
}

static void point_nondet(p256_point *p) {
    for (size_t i = 0; i < P256_FE_WORDS; i++) {
        p->x.word[i] = nondet_u32();
        p->y.word[i] = nondet_u32();
        p->z.word[i] = nondet_u32();
    }
}

static void prove_add_aliasing(void) {
    p256_wide_point a;
    p256_wide_point b;
    p256_wide_point o;

    wide_point_nondet(&a);
    wide_point_nondet(&b);
    p256_wide_point_add(&o, &a, &b);

    wide_point_nondet(&a);
    wide_point_nondet(&b);
    p256_wide_point_add(&a, &a, &b); // o == a

    wide_point_nondet(&a);
    wide_point_nondet(&b);
    p256_wide_point_add(&b, &a, &b); // o == b

    wide_point_nondet(&a);
    p256_wide_point_add(&a, &a, &a); // o == a == b
}

static void prove_add_affine(void) {
    p256_wide_point a;
    p256_wide_point o;
    p256_wide_affine b;

    wide_point_nondet(&a);
    for (size_t i = 0; i < P256_WIDE_FE_WORDS; i++) {
        b.x.word[i] = nondet_u64();
        b.y.word[i] = nondet_u64();
    }
    p256_wide_point_add_affine(&o, &a, &b);
    wide_point_nondet(&a);
    p256_wide_point_add_affine(&a, &a, &b); // o == a, the shape the base multiplication adds in
}

static void prove_double(void) {
    p256_wide_point a;
    p256_wide_point o;

    wide_point_nondet(&a);
    p256_wide_point_double(&o, &a);
    wide_point_nondet(&a);
    p256_wide_point_double(&a, &a); // o == a, the shape a multiplication doubles in
}

static void prove_from_bytes(void) {
    uint8_t in[P256_POINT_LEN];
    p256_point o;
    fill_nondet(in, sizeof in);
    uint32_t valid = p256_wide_point_from_bytes(&o, in);
    __CPROVER_assert(valid == 0 || valid == UINT32_MAX,
                     "p256_wide_point_from_bytes: the answer is a mask, not a flag");
}

static void prove_affine(void) {
    p256_point a;
    uint8_t x[P256_FE_LEN];
    uint8_t y[P256_FE_LEN];

    point_nondet(&a);
    uint32_t finite = p256_wide_point_affine(x, y, &a);
    __CPROVER_assert(finite == 0 || finite == UINT32_MAX,
                     "p256_wide_point_affine: the answer is a mask, not a flag");
    point_nondet(&a);
    finite = p256_wide_point_affine(x, NULL, &a); // the shape p256_sign.c reads x in
    __CPROVER_assert(finite == 0 || finite == UINT32_MAX,
                     "p256_wide_point_affine: the answer is a mask without a y output");
}

static void prove_copies(void) {
    p256_point portable;
    p256_wide_point wide;
    point_nondet(&portable);
    p256_wide_point_from_portable(&wide, &portable);
    p256_wide_point_to_portable(&portable, &wide);
}

int main(void) {
    prove_add_aliasing();
    prove_add_affine();
    prove_double();
    prove_from_bytes();
    prove_affine();
    prove_copies();
    return 0;
}
