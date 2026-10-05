// Proves, for p384_wide_point.c: every routine that computes on a key or
// on a point is memory-safe and UB-free, and every limb array it hands
// the field is below p, which is what the field's contract takes.
//
//   point_double, point_add       : any points, into a third point and in
//                                   place, as the scalar multiplication
//                                   calls them
//   odd_multiples                 : the whole table of eight
//   p384_wide_point_decode        : any 96 bytes; a key it takes is three
//                                   coordinates below p
//   p384_wide_point_is_infinity,
//   p384_wide_point_x_is_r        : any point and any r in 1..n-1
//
// Layered. The three routines of p384_wide_field.c that the points
// multiply, add and subtract with are the contracts of
// proof/p384_wide_stubs.h.
//
// Not unrolled: the loop of p384_wide_double_mul, 385 rounds of a
// doubling and two additions. Its body is point_double and add_multiple,
// which run here on any point and any digit, and its only
// iteration-dependent accesses are the two digit arrays at i, below the
// larger of the two counts signed_digits returned, which is at most
// DIGITS_LEN. p384_wide_double_mul's first statements are three
// to_montgomery calls on constants, odd_multiples twice and signed_digits
// twice. proof/p384_wide_digits_harness.c runs signed_digits and
// add_multiple.
//
// Not proven here: that a result is the sum of two points, or that the
// digits spell the scalar. bin/p384_equiv_test holds the verdict the
// points lead to against p384.c's.
#include "p384_wide_stubs.h"

#include "p384_wide_point.c"

int main(void) {
    p384_wide_point a;
    p384_wide_point b;
    p384_wide_point o;
    p384_wide_point table[TABLE_LEN];

    havoc_point(&a);
    point_double(&o, &a);
    __CPROVER_assert(point_below(&o), "point_double: a point below p");
    point_double(&a, &a); // in place, as the scalar multiplication doubles its sum

    havoc_point(&a);
    havoc_point(&b);
    point_add(&o, &a, &b);
    __CPROVER_assert(point_below(&o), "point_add: a point below p");
    point_add(&a, &a, &b); // over its left operand, as add_multiple calls it

    havoc_point(&a);
    odd_multiples(table, &a);
    __CPROVER_assert(point_below(&table[TABLE_LEN - 1]), "odd_multiples: points below p");

    // A key: any 96 bytes.
    uint8_t pub[P384_PUB_LEN];
    fill_nondet(pub, sizeof pub);
    if (p384_wide_point_decode(&a, pub)) {
        __CPROVER_assert(point_below(&a), "decode: a key it takes is a point below p");
    }

    // The last comparison: any point, and any r in 1..n-1.
    uint64_t k[LIMBS];
    havoc_point(&a);
    havoc_below(k, &p384_wide_modn);
    __CPROVER_assume(!p384_wide_is_zero(k));
    (void)p384_wide_point_is_infinity(&a);
    int same = p384_wide_point_x_is_r(&a, k);
    __CPROVER_assert(same == 0 || same == 1, "x comparison: 0 or 1");
    return 0;
}
