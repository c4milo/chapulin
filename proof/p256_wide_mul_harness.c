// Proves, for p256_wide_mul.c, the whole of p256_wide_base_mul and
// p256_wide_mul over an unconstrained scalar and an unconstrained point,
// every window of the shipped loops in one formula each:
//
//   memory safety and absence of UB, and no unsigned wrap
//   (--unsigned-overflow-check on the launch line). The accesses that move
//   with a loop counter are proven in bounds at every trip, on the shipped
//   loops: the scalar's word and shift for each bit a digit reads, the
//   table's row for each window, the entry of a row for each step of a
//   scan, and the eight multiples of the point;
//
//   that every mask handed to p256_wide_fe_cmov is 0 or all ones, which
//   proof/p256_wide_field_stubs.h asserts: the sign of each digit, and the
//   mask of the correction for an even scalar;
//
//   that the wipes at the end of each multiplication stay inside the objects
//   they name, the eight multiples among them (ct_wipe's stub).
//
// The point formulas are the stubs in proof/p256_wide_point_stubs.h and the
// field's negation and conditional move the stubs in
// proof/p256_wide_field_stubs.h, so nothing here depends on a coordinate.
// The digits, the scans and p256_wide_mask run on their real bodies, and
// the table is the shipped p256_wide_table.c, which the launch line links.
// proof/p256_wide_digit_harness.c proves what the digits and the scans
// compute.
//
// Not proven here: that either multiplication computes k times its point.
// bin/p256_equiv_test holds both to p256_point.c's on edge and random
// scalars, and bin/diff_p256_wide to the Lean spec.
#include "p256_wide_field_stubs.h"
#include "p256_wide_point_stubs.h"

#include "p256_wide_mul.c"

static void scalar_nondet(p256_scalar *k) {
    for (size_t i = 0; i < P256_SCALAR_WORDS; i++) {
        k->word[i] = nondet_u32();
    }
}

int main(void) {
    p256_scalar k;
    p256_point p;
    p256_point o;

    scalar_nondet(&k);
    p256_wide_base_mul(&o, &k);

    scalar_nondet(&k);
    for (size_t i = 0; i < P256_FE_WORDS; i++) {
        p.x.word[i] = nondet_u32();
        p.y.word[i] = nondet_u32();
        p.z.word[i] = nondet_u32();
    }
    p256_wide_mul(&o, &k, &p);
    return 0;
}
