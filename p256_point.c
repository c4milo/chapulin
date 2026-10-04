// Constant-time P-256 point arithmetic (see p256_point.h for the
// contracts). Every coordinate is a Montgomery-domain p256_fe, every
// choice is a masked exchange, and the one loop runs a literal 256
// times.
#include "p256_point.h"

#include <stddef.h>

#include "ct.h"
#include "p256_field.h"
#include "p256_scalar.h"

// The curve coefficient b and the generator G, each already multiplied by
// R = 2^256 so that they sit in the Montgomery domain the routines below
// work in. test/gen_p256_sign_vectors.py recomputes all three from the
// SEC 2 values and stops if any limb here differs.
//
// b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
static const p256_fe B_MONT = {
    {0x29c4bddf, 0xd89cdf62, 0x78843090, 0xacf005cd, 0xf7212ed6, 0xe5a220ab, 0x04874834,
     0xdc30061d}
};
// G.x = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
static const p256_fe GX_MONT = {
    {0x18a9143c, 0x79e730d4, 0x5fedb601, 0x75ba95fc, 0x77622510, 0x79fb732b, 0xa53755c6,
     0x18905f76}
};
// G.y = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
static const p256_fe GY_MONT = {
    {0xce95560a, 0xddf25357, 0xba19e45c, 0x8b4ab8e4, 0xdd21f325, 0xd2e88688, 0x25885d85,
     0x8571ff18}
};

const p256_point p256_point_generator = {
    GX_MONT,
    GY_MONT,
    // Z is R mod p, the Montgomery form of 1: G is given affine, and an
    // affine point is the projective one with Z = 1.
    {{0x00000001, 0x00000000, 0x00000000, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
      0x00000000}},
};

const p256_point p256_point_infinity = {
    {{0, 0, 0, 0, 0, 0, 0, 0}},
    // Y is R mod p, the Montgomery form of 1. Any nonzero Y stands for
    // the same point; one is the value the affine reader would hand back.
    {{0x00000001, 0x00000000, 0x00000000, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
      0x00000000}},
    {{0, 0, 0, 0, 0, 0, 0, 0}},
};

// Renes-Costello-Batina Algorithm 4, the complete addition for a = -3,
// step for step in the paper's order and with the paper's register names.
// Keeping the order and the names is what lets an auditor read the
// formula against the paper without rewriting either; the alternative,
// folding steps together for speed, makes the two unreadable against each
// other. Every step is a field operation over operands already below p,
// so nothing here can overflow.
void p256_point_add(p256_point *o, const p256_point *a, const p256_point *b) {
    p256_fe t0;
    p256_fe t1;
    p256_fe t2;
    p256_fe t3;
    p256_fe t4;
    p256_fe x3;
    p256_fe y3;
    p256_fe z3;

    p256_fe_mul(&t0, &a->x, &b->x);
    p256_fe_mul(&t1, &a->y, &b->y);
    p256_fe_mul(&t2, &a->z, &b->z);
    p256_fe_add(&t3, &a->x, &a->y);
    p256_fe_add(&t4, &b->x, &b->y);
    p256_fe_mul(&t3, &t3, &t4);
    p256_fe_add(&t4, &t0, &t1);
    p256_fe_sub(&t3, &t3, &t4);
    p256_fe_add(&t4, &a->y, &a->z);
    p256_fe_add(&x3, &b->y, &b->z);
    p256_fe_mul(&t4, &t4, &x3);
    p256_fe_add(&x3, &t1, &t2);
    p256_fe_sub(&t4, &t4, &x3);
    p256_fe_add(&x3, &a->x, &a->z);
    p256_fe_add(&y3, &b->x, &b->z);
    p256_fe_mul(&x3, &x3, &y3);
    p256_fe_add(&y3, &t0, &t2);
    p256_fe_sub(&y3, &x3, &y3);
    p256_fe_mul(&z3, &B_MONT, &t2);
    p256_fe_sub(&x3, &y3, &z3);
    p256_fe_add(&z3, &x3, &x3);
    p256_fe_add(&x3, &x3, &z3);
    p256_fe_sub(&z3, &t1, &x3);
    p256_fe_add(&x3, &t1, &x3);
    p256_fe_mul(&y3, &B_MONT, &y3);
    p256_fe_add(&t1, &t2, &t2);
    p256_fe_add(&t2, &t1, &t2);
    p256_fe_sub(&y3, &y3, &t2);
    p256_fe_sub(&y3, &y3, &t0);
    p256_fe_add(&t1, &y3, &y3);
    p256_fe_add(&y3, &t1, &y3);
    p256_fe_add(&t1, &t0, &t0);
    p256_fe_add(&t0, &t1, &t0);
    p256_fe_sub(&t0, &t0, &t2);
    p256_fe_mul(&t1, &t4, &y3);
    p256_fe_mul(&t2, &t0, &y3);
    p256_fe_mul(&y3, &x3, &z3);
    p256_fe_add(&y3, &y3, &t2);
    p256_fe_mul(&x3, &t3, &x3);
    p256_fe_sub(&x3, &x3, &t1);
    p256_fe_mul(&z3, &t4, &z3);
    p256_fe_mul(&t1, &t3, &t0);
    p256_fe_add(&z3, &z3, &t1);

    // o may alias a or b, so the three coordinates move only now, after
    // every read of a and b is done.
    o->x = x3;
    o->y = y3;
    o->z = z3;
}

void p256_point_cswap(p256_point *a, p256_point *b, uint32_t mask) {
    p256_fe_cswap(&a->x, &b->x, mask);
    p256_fe_cswap(&a->y, &b->y, mask);
    p256_fe_cswap(&a->z, &b->z, mask);
}

// One round of the Montgomery ladder, for bit i of k: exchange when the
// bit is set, add, double, exchange back. A function of its own so
// proof/p256_point_ladder_harness.c can prove one round over any k and
// any i in [0, 255] -- the shipped round, not a copy -- and let the loop
// in p256_point_mul carry it 256 times, the way x25519.c's step() and
// ladder() divide the same work. The bit becomes a mask by a shift and a
// subtraction of one, never by negating the bit: `0 - bit` is the shape
// gcc rewrites into a multiply by a secret bit (ct.h,
// https://github.com/c4milo/chapulin/issues/106).
static void ladder_round(p256_point *r0, p256_point *r1, p256_point *sum, const p256_scalar *k,
                         int i) {
    uint32_t bit = (k->limb[i >> 5] >> (i & 31)) & 1U;
    uint32_t mask = ~(bit - 1U); // clear bit -> zero, set bit -> all ones
    p256_point_cswap(r0, r1, mask);
    p256_point_add(sum, r0, r1);
    p256_point_add(r0, r0, r0);
    *r1 = *sum;
    p256_point_cswap(r0, r1, mask);
}

void p256_point_mul(p256_point *o, const p256_scalar *k, const p256_point *p) {
    p256_point r0 = p256_point_infinity;
    p256_point r1 = *p;
    p256_point sum;

    // Most significant bit first: 256 rounds, each the same work whatever
    // the bit holds.
    for (int i = P256_SCALAR_LIMBS * 32 - 1; i >= 0; i--) {
        ladder_round(&r0, &r1, &sum, k, i);
    }
    *o = r0;

    ct_wipe(&r0, sizeof r0);
    ct_wipe(&r1, sizeof r1);
    ct_wipe(&sum, sizeof sum);
}

void p256_point_base_mul(p256_point *o, const p256_scalar *k) {
    p256_point_mul(o, k, &p256_point_generator);
}

uint32_t p256_point_from_bytes(p256_point *o, const uint8_t in[P256_POINT_LEN]) {
    p256_fe x;
    p256_fe y;
    p256_fe lhs;
    p256_fe rhs;
    p256_fe three_x;

    // SEC 1 section 2.3.3's tag for an uncompressed point. Both returns
    // below read the peer's bytes, which are public.
    if (in[0] != 0x04) {
        return 0;
    }
    p256_fe_from_bytes(&x, in + 1);
    p256_fe_from_bytes(&y, in + 1 + P256_FE_LEN);
    if ((p256_fe_reduced_mask(&x) & p256_fe_reduced_mask(&y)) == 0) {
        return 0;
    }

    p256_fe_to_mont(&o->x, &x);
    p256_fe_to_mont(&o->y, &y);
    o->z = p256_fe_one_mont;

    // y^2 = x^3 - 3x + b. Three additions stand in for the constant 3,
    // which keeps one more derived constant out of the file.
    p256_fe_sqr(&lhs, &o->y);
    p256_fe_sqr(&rhs, &o->x);
    p256_fe_mul(&rhs, &rhs, &o->x);
    p256_fe_add(&three_x, &o->x, &o->x);
    p256_fe_add(&three_x, &three_x, &o->x);
    p256_fe_sub(&rhs, &rhs, &three_x);
    p256_fe_add(&rhs, &rhs, &B_MONT);
    return p256_fe_equal_mask(&lhs, &rhs);
}

uint32_t p256_point_affine(uint8_t x[P256_FE_LEN], uint8_t y[P256_FE_LEN], const p256_point *a) {
    p256_fe z_inverse;
    p256_fe coord;

    // p256_fe_inv sends 0 to 0, so an infinite point leaves zero bytes
    // here and the mask below is what tells the caller to discard them.
    p256_fe_inv(&z_inverse, &a->z);
    p256_fe_mul(&coord, &a->x, &z_inverse);
    p256_fe_from_mont(&coord, &coord);
    p256_fe_to_bytes(x, &coord);
    if (y != NULL) {
        p256_fe_mul(&coord, &a->y, &z_inverse);
        p256_fe_from_mont(&coord, &coord);
        p256_fe_to_bytes(y, &coord);
    }

    uint32_t finite = ~p256_fe_zero_mask(&a->z);
    ct_wipe(&z_inverse, sizeof z_inverse);
    ct_wipe(&coord, sizeof coord);
    return finite;
}

uint32_t p256_point_affine_x(uint8_t out[P256_FE_LEN], const p256_point *a) {
    return p256_point_affine(out, NULL, a);
}
