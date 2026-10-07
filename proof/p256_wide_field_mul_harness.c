// Proves: p256_wide_fe_mul, p256_wide_fe_sqr, p256_wide_fe_to_mont,
// p256_wide_fe_from_mont and sqr_times are memory-safe and UB-free over
// fully nondet words and wrap no unsigned value (--unsigned-overflow-check
// on the launch line), in every aliasing shape a point formula and
// p256_wide_fe_inv use: the output distinct from both inputs, over the
// first, over the second, and with both inputs one object.
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
// p256_wide_fe_inv is not run whole. Its chain is 267 of the calls proven
// here, in the shapes proven here, on its own locals, with no index and no
// count that is not a literal. sqr_times runs here at a count of 3, in both
// shapes the chain calls it in, which is the one loop in the chain. The
// whole chain in one formula costs symbolic execution, not the solver: each
// product takes the address of 17 locals, cbmc's time grows with the square
// of the objects it tracks, 32 squarings took 57 s where 8 took 3, and the
// whole chain was stopped after 11 minutes with no formula yet.
//
// Not proven here: the product's value, as proof/p256_wide_stubs.h says, and
// so that the chain computes a^(p-2). p256_wide_field_harness.c proves the
// reduction's bound on its own, below p for any product of two elements.
// tools/p256_wide.py checks that the runs of bits the chain writes are
// p - 2, and bin/p256_equiv_test holds the inverse to p256_fe_inv's and to
// Python's.
#include "p256_wide_stubs.h"

#include "p256_wide_field.c"

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
    p256_wide_fe_sqr(&a, &a); // the shape sqr_times squares in
    fe_nondet(&a);
    p256_wide_fe_to_mont(&o, &a);
    fe_nondet(&a);
    p256_wide_fe_from_mont(&a, &a); // the shape p256_wide_point_affine uses
    fe_nondet(&a);
    sqr_times(&o, &a, 3); // p256_wide_fe_inv's first use: a power into t
    fe_nondet(&a);
    sqr_times(&a, &a, 3); // and its later ones: t over itself
    return 0;
}
