// Proves: p256_wide_fe_mul, p256_wide_fe_sqr, p256_wide_fe_to_mont,
// p256_wide_fe_from_mont and p256_wide_fe_inv are memory-safe and UB-free
// over fully nondet words and wrap no unsigned value
// (--unsigned-overflow-check on the launch line), in every aliasing shape a
// point formula uses: the output distinct from both inputs, over the first,
// over the second, and with both inputs one object. p256_wide_fe_inv wipes
// its one temporary through ct_wipe, whose stub proves the wipe inside it.
//
// The four rows of each product are the contract in proof/p256_wide_stubs.h,
// which p256_wide_row_harness.c discharges on the real multiply, and so is a
// square's ten products, which p256_wide_sqr_harness.c discharges. What runs
// here on the shipped code is everything between the rows and the output:
// which words each row is handed, the four rounds of the reduction, the one
// sum in a round that has to fit, the carry of the round before beside the
// high word of that round's multiple of p, and the conditional subtraction.
// The product over the real multiply, 16 widened 64x64 multipliers in one
// formula, also converged, in 165 s at 474 MB, and has no launch line: it
// states the row's claim four more times and nothing else.
//
// p256_wide_fe_inv runs over a contract of p256_wide_inverse, below: it reads
// y and the modulus and writes any four words. The four
// p256_wide_inverse harnesses prove that routine's own accesses and steps.
//
// Not proven here: the product's value, as proof/p256_wide_stubs.h says, and
// so that p256_wide_fe_inv's product with R^3 moves the inverse into the
// Montgomery domain. p256_wide_field_harness.c proves the reduction's bound
// on its own, below p for any product of two elements. tools/p256_wide.py
// checks that the constant is 2^768 mod p, and bin/p256_equiv_test holds the
// inverse to p256_fe_inv's and to Python's.
#include "p256_wide_stubs.h"

#include "p256_wide_field.c"

// p256_wide_inverse reads y and the modulus and writes any four words.
void p256_wide_inverse(uint64_t o[P256_WIDE_INVERSE_WORDS],
                       const uint64_t y[P256_WIDE_INVERSE_WORDS], const p256_wide_modulus *m) {
    __CPROVER_assert(__CPROVER_r_ok(y, sizeof(uint64_t) * P256_WIDE_INVERSE_WORDS) &&
                         __CPROVER_r_ok(m, sizeof *m) &&
                         __CPROVER_w_ok(o, sizeof(uint64_t) * P256_WIDE_INVERSE_WORDS),
                     "p256_wide_inverse: y and the modulus readable, the four words writable");
    for (size_t i = 0; i < P256_WIDE_INVERSE_WORDS; i++) {
        o[i] = nondet_u64();
    }
}

static void fe_nondet(p256_wide_fe *f) {
    for (size_t i = 0; i < P256_WIDE_FE_WORDS; i++) {
        f->word[i] = nondet_u64();
    }
}

int main(void) {
    p256_wide_fe a;
    p256_wide_fe b;
    p256_wide_fe o;

    fe_nondet(&a);
    fe_nondet(&b);
    p256_wide_fe_mul(&o, &a, &b);
    fe_nondet(&a);
    fe_nondet(&b);
    p256_wide_fe_mul(&a, &a, &b); // o == a
    fe_nondet(&a);
    fe_nondet(&b);
    p256_wide_fe_mul(&b, &a, &b); // o == b
    fe_nondet(&a);
    p256_wide_fe_mul(&a, &a, &a); // all three one object
    fe_nondet(&a);
    p256_wide_fe_sqr(&o, &a);
    fe_nondet(&a);
    p256_wide_fe_sqr(&a, &a);
    fe_nondet(&a);
    p256_wide_fe_to_mont(&o, &a);
    fe_nondet(&a);
    p256_wide_fe_from_mont(&a, &a); // the shape p256_wide_point_affine uses
    fe_nondet(&a);
    p256_wide_fe_inv(&o, &a);
    fe_nondet(&a);
    p256_wide_fe_inv(&a, &a);
    return 0;
}
