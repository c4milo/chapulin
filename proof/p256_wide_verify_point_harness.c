// Proves, for p256_wide_verify_point.c: every routine that computes on a
// key or on a point is memory-safe and UB-free.
//
//   point_double, point_add,
//   point_add_affine                    : any points, into another point
//                                         and in place, as the double
//                                         multiplication calls them
//   odd_multiples                       : the whole table of eight
//   p256_wide_jacobian_from_key         : any point of p256_point.h's type
//   p256_wide_jacobian_is_infinity,
//   p256_wide_jacobian_x_is_r           : any point and any r
//
// Layered. The routines of p256_wide_field.c the points compute with are
// the contracts of proof/p256_wide_field_stubs.h, whose predicates answer
// an unconstrained mask, so every branch on a coordinate is taken both
// ways. The launch line links p256_wide_table.c, whose row 0 the additions
// of G's multiples read.
//
// Not unrolled: the loop of p256_wide_jacobian_double_mul, 257 rounds of a
// doubling and two additions. Its body is point_double, add_g_multiple and
// add_q_multiple, which run here and in
// proof/p256_wide_verify_digits_harness.c on any point and any digit, and
// its only accesses that depend on the round are the two digit arrays at
// i, below the larger of the two counts signed_digits returned, which is
// at most DIGITS_LEN.
//
// Not proven here: that a result is the sum of two points, or that the
// comparison answers for the point's x. bin/p256_verify_equiv_test holds
// the verdict the points lead to against p256.c's.
#include "p256_wide_field_stubs.h"

#include "p256_wide_verify_point.c"

static void havoc_point(p256_wide_jacobian *p) {
    havoc_wide_fe(&p->x);
    havoc_wide_fe(&p->y);
    havoc_wide_fe(&p->z);
}

int main(void) {
    p256_wide_jacobian a;
    p256_wide_jacobian b;
    p256_wide_jacobian o;
    p256_wide_jacobian table[TABLE_LEN];
    p256_wide_affine entry;

    havoc_point(&a);
    point_double(&o, &a);
    point_double(&a, &a); // in place, as the double multiplication doubles its sum

    havoc_point(&a);
    havoc_point(&b);
    point_add(&o, &a, &b);
    point_add(&a, &a, &b); // over its left operand, as add_q_multiple calls it

    havoc_point(&a);
    havoc_wide_fe(&entry.x);
    havoc_wide_fe(&entry.y);
    point_add_affine(&o, &a, &entry);
    point_add_affine(&a, &a, &entry); // over its left operand, as add_g_multiple calls it

    havoc_point(&a);
    odd_multiples(table, &a);

    // A key: any point of p256_point.h's type.
    p256_point key;
    for (size_t i = 0; i < P256_FE_WORDS; i++) {
        key.x.word[i] = nondet_u32();
        key.y.word[i] = nondet_u32();
        key.z.word[i] = nondet_u32();
    }
    p256_wide_jacobian_from_key(&a, &key);

    // The last comparison: any point and any r.
    p256_scalar r;
    for (size_t i = 0; i < P256_SCALAR_WORDS; i++) {
        r.word[i] = nondet_u32();
    }
    havoc_point(&a);
    int infinite = p256_wide_jacobian_is_infinity(&a);
    __CPROVER_assert(infinite == 0 || infinite == 1, "infinity test: 0 or 1");
    int same = p256_wide_jacobian_x_is_r(&a, &r);
    __CPROVER_assert(same == 0 || same == 1, "x comparison: 0 or 1");
    return 0;
}
