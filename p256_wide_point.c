// P-256 points over the wide field (see p256_wide_point.h for the contracts). Every
// coordinate is a Montgomery-domain p256_wide_fe, and the formula is p256_point.c's with that
// file's register names, so the two read against each other line by line.
#include "p256_wide_point.h"

#ifdef CH_CPU_RUNTIME

#include <stddef.h>

#include "ct.h"
#include "p256_wide_field.h"

// The curve coefficient b, multiplied by R = 2^256: p256_point.c's B_MONT in 64-bit limbs.
// tools/p256_wide.py recomputes it from the SEC 2 value and stops if a limb differs.
//
// b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
static const p256_wide_fe B_MONT = {
    {UINT64_C(0xd89cdf6229c4bddf), UINT64_C(0xacf005cd78843090), UINT64_C(0xe5a220abf7212ed6),
     UINT64_C(0xdc30061d04874834)}
};

void p256_wide_point_from_portable(p256_wide_point *o, const p256_point *a) {
    p256_wide_fe_from_portable(&o->x, &a->x);
    p256_wide_fe_from_portable(&o->y, &a->y);
    p256_wide_fe_from_portable(&o->z, &a->z);
}

void p256_wide_point_to_portable(p256_point *o, const p256_wide_point *a) {
    p256_wide_fe_to_portable(&o->x, &a->x);
    p256_wide_fe_to_portable(&o->y, &a->y);
    p256_wide_fe_to_portable(&o->z, &a->z);
}

// Renes-Costello-Batina Algorithm 4, the complete addition for a = -3, step for step in the
// paper's order and with the paper's register names, as p256_point_add writes it.
void p256_wide_point_add(p256_wide_point *o, const p256_wide_point *a, const p256_wide_point *b) {
    p256_wide_fe t0;
    p256_wide_fe t1;
    p256_wide_fe t2;
    p256_wide_fe t3;
    p256_wide_fe t4;
    p256_wide_fe x3;
    p256_wide_fe y3;
    p256_wide_fe z3;

    p256_wide_fe_mul(&t0, &a->x, &b->x);
    p256_wide_fe_mul(&t1, &a->y, &b->y);
    p256_wide_fe_mul(&t2, &a->z, &b->z);
    p256_wide_fe_add(&t3, &a->x, &a->y);
    p256_wide_fe_add(&t4, &b->x, &b->y);
    p256_wide_fe_mul(&t3, &t3, &t4);
    p256_wide_fe_add(&t4, &t0, &t1);
    p256_wide_fe_sub(&t3, &t3, &t4);
    p256_wide_fe_add(&t4, &a->y, &a->z);
    p256_wide_fe_add(&x3, &b->y, &b->z);
    p256_wide_fe_mul(&t4, &t4, &x3);
    p256_wide_fe_add(&x3, &t1, &t2);
    p256_wide_fe_sub(&t4, &t4, &x3);
    p256_wide_fe_add(&x3, &a->x, &a->z);
    p256_wide_fe_add(&y3, &b->x, &b->z);
    p256_wide_fe_mul(&x3, &x3, &y3);
    p256_wide_fe_add(&y3, &t0, &t2);
    p256_wide_fe_sub(&y3, &x3, &y3);
    p256_wide_fe_mul(&z3, &B_MONT, &t2);
    p256_wide_fe_sub(&x3, &y3, &z3);
    p256_wide_fe_add(&z3, &x3, &x3);
    p256_wide_fe_add(&x3, &x3, &z3);
    p256_wide_fe_sub(&z3, &t1, &x3);
    p256_wide_fe_add(&x3, &t1, &x3);
    p256_wide_fe_mul(&y3, &B_MONT, &y3);
    p256_wide_fe_add(&t1, &t2, &t2);
    p256_wide_fe_add(&t2, &t1, &t2);
    p256_wide_fe_sub(&y3, &y3, &t2);
    p256_wide_fe_sub(&y3, &y3, &t0);
    p256_wide_fe_add(&t1, &y3, &y3);
    p256_wide_fe_add(&y3, &t1, &y3);
    p256_wide_fe_add(&t1, &t0, &t0);
    p256_wide_fe_add(&t0, &t1, &t0);
    p256_wide_fe_sub(&t0, &t0, &t2);
    p256_wide_fe_mul(&t1, &t4, &y3);
    p256_wide_fe_mul(&t2, &t0, &y3);
    p256_wide_fe_mul(&y3, &x3, &z3);
    p256_wide_fe_add(&y3, &y3, &t2);
    p256_wide_fe_mul(&x3, &t3, &x3);
    p256_wide_fe_sub(&x3, &x3, &t1);
    p256_wide_fe_mul(&z3, &t4, &z3);
    p256_wide_fe_mul(&t1, &t3, &t0);
    p256_wide_fe_add(&z3, &z3, &t1);

    // o may alias a or b, so the three coordinates move only now, after every read of a and b
    // is done.
    o->x = x3;
    o->y = y3;
    o->z = z3;
}

// Renes-Costello-Batina Algorithm 5, the complete mixed addition for a = -3, step for step
// in the paper's order and with the paper's register names. It is Algorithm 4 with Z2 = 1:
// the products by Z2 are gone, and what is left computes the same three coordinates.
void p256_wide_point_add_affine(p256_wide_point *o, const p256_wide_point *a,
                                const p256_wide_affine *b) {
    p256_wide_fe t0;
    p256_wide_fe t1;
    p256_wide_fe t2;
    p256_wide_fe t3;
    p256_wide_fe t4;
    p256_wide_fe x3;
    p256_wide_fe y3;
    p256_wide_fe z3;

    p256_wide_fe_mul(&t0, &a->x, &b->x);
    p256_wide_fe_mul(&t1, &a->y, &b->y);
    p256_wide_fe_add(&t3, &b->x, &b->y);
    p256_wide_fe_add(&t4, &a->x, &a->y);
    p256_wide_fe_mul(&t3, &t3, &t4);
    p256_wide_fe_add(&t4, &t0, &t1);
    p256_wide_fe_sub(&t3, &t3, &t4);
    p256_wide_fe_mul(&t4, &b->y, &a->z);
    p256_wide_fe_add(&t4, &t4, &a->y);
    p256_wide_fe_mul(&y3, &b->x, &a->z);
    p256_wide_fe_add(&y3, &y3, &a->x);
    p256_wide_fe_mul(&z3, &B_MONT, &a->z);
    p256_wide_fe_sub(&x3, &y3, &z3);
    p256_wide_fe_add(&z3, &x3, &x3);
    p256_wide_fe_add(&x3, &x3, &z3);
    p256_wide_fe_sub(&z3, &t1, &x3);
    p256_wide_fe_add(&x3, &t1, &x3);
    p256_wide_fe_mul(&y3, &B_MONT, &y3);
    p256_wide_fe_add(&t1, &a->z, &a->z);
    p256_wide_fe_add(&t2, &t1, &a->z);
    p256_wide_fe_sub(&y3, &y3, &t2);
    p256_wide_fe_sub(&y3, &y3, &t0);
    p256_wide_fe_add(&t1, &y3, &y3);
    p256_wide_fe_add(&y3, &t1, &y3);
    p256_wide_fe_add(&t1, &t0, &t0);
    p256_wide_fe_add(&t0, &t1, &t0);
    p256_wide_fe_sub(&t0, &t0, &t2);
    p256_wide_fe_mul(&t1, &t4, &y3);
    p256_wide_fe_mul(&t2, &t0, &y3);
    p256_wide_fe_mul(&y3, &x3, &z3);
    p256_wide_fe_add(&y3, &y3, &t2);
    p256_wide_fe_mul(&x3, &t3, &x3);
    p256_wide_fe_sub(&x3, &x3, &t1);
    p256_wide_fe_mul(&z3, &t4, &z3);
    p256_wide_fe_mul(&t1, &t3, &t0);
    p256_wide_fe_add(&z3, &z3, &t1);

    // o may alias a, so the three coordinates move only now.
    o->x = x3;
    o->y = y3;
    o->z = z3;
}

uint32_t p256_wide_point_from_bytes(p256_point *o, const uint8_t in[P256_POINT_LEN]) {
    p256_wide_point point;
    p256_wide_fe x;
    p256_wide_fe y;
    p256_wide_fe lhs;
    p256_wide_fe rhs;
    p256_wide_fe three_x;

    // SEC 1 section 2.3.3's tag for an uncompressed point. Both returns below read the peer's
    // bytes, which are public.
    if (in[0] != 0x04) {
        return 0;
    }
    p256_wide_fe_from_bytes(&x, in + 1);
    p256_wide_fe_from_bytes(&y, in + 1 + P256_FE_LEN);
    if ((p256_wide_fe_reduced_mask(&x) & p256_wide_fe_reduced_mask(&y)) == 0) {
        return 0;
    }

    p256_wide_fe_to_mont(&point.x, &x);
    p256_wide_fe_to_mont(&point.y, &y);
    point.z = p256_wide_fe_one_mont;
    p256_wide_point_to_portable(o, &point);

    // y^2 = x^3 - 3x + b, with three additions for the constant 3, as p256_point_from_bytes
    // writes it.
    p256_wide_fe_sqr(&lhs, &point.y);
    p256_wide_fe_sqr(&rhs, &point.x);
    p256_wide_fe_mul(&rhs, &rhs, &point.x);
    p256_wide_fe_add(&three_x, &point.x, &point.x);
    p256_wide_fe_add(&three_x, &three_x, &point.x);
    p256_wide_fe_sub(&rhs, &rhs, &three_x);
    p256_wide_fe_add(&rhs, &rhs, &B_MONT);
    // The mask is all ones or zero, and its low half is p256_point.h's mask.
    return (uint32_t)p256_wide_fe_equal_mask(&lhs, &rhs);
}

uint32_t p256_wide_point_affine(uint8_t x[P256_FE_LEN], uint8_t y[P256_FE_LEN],
                                const p256_point *a) {
    p256_wide_point point;
    p256_wide_fe z_inverse;
    p256_wide_fe coord;

    p256_wide_point_from_portable(&point, a);
    // p256_wide_fe_inv sends 0 to 0, so an infinite point leaves zero bytes here and the mask
    // below is what tells the caller to discard them.
    p256_wide_fe_inv(&z_inverse, &point.z);
    p256_wide_fe_mul(&coord, &point.x, &z_inverse);
    p256_wide_fe_from_mont(&coord, &coord);
    p256_wide_fe_to_bytes(x, &coord);
    if (y != NULL) {
        p256_wide_fe_mul(&coord, &point.y, &z_inverse);
        p256_wide_fe_from_mont(&coord, &coord);
        p256_wide_fe_to_bytes(y, &coord);
    }

    uint64_t finite = ~p256_wide_fe_zero_mask(&point.z);
    ct_wipe(&point, sizeof point);
    ct_wipe(&z_inverse, sizeof z_inverse);
    ct_wipe(&coord, sizeof coord);
    return (uint32_t)finite;
}

#endif // CH_CPU_RUNTIME
