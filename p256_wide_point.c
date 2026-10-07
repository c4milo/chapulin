// P-256 points over the wide field (see p256_wide_point.h for the contracts). Every
// coordinate is a Montgomery-domain p256_wide_fe. The two complete additions are
// p256_point.c's with that file's register names, so the two read against each other line by
// line. The incomplete additions, the Jacobian doubling and the two conversions have no
// counterpart there.
#include "p256_wide_point.h"

#ifdef CH_CPU_RUNTIME

#include <stddef.h>

#include "ct.h"
#include "p256_wide_field.h"

// The curve coefficient b, multiplied by R = 2^256: p256_point.c's B_MONT in 64-bit words.
// tools/p256_wide.py recomputes it from the SEC 2 value and stops if a word differs.
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

// The Explicit-Formulas Database's madd-1998-cmo, step for step with the database's names in
// lower case: the mixed addition of Cohen, Miyaji and Ono in homogeneous projective
// coordinates, 9 products and 2 squares where Algorithm 5 above runs 11 products and 2 products
// by b. The database's A is x3_numerator: a sum's x is A / (v^2 Z1). It is not complete: v is
// zero when a's x equals b's and when a is the point at infinity, and then so are X3 and Z3. So
// a must be finite and its x must not be b's. spec/lean/Spec/P256WidePoint.lean holds the same
// steps and proves that they add under that condition, and p256_wide_mul.c says why
// p256_wide_base_mul meets it.
void p256_wide_point_add_affine_incomplete(p256_wide_point *o, const p256_wide_point *a,
                                           const p256_wide_affine *b) {
    p256_wide_fe u;
    p256_wide_fe uu;
    p256_wide_fe v;
    p256_wide_fe vv;
    p256_wide_fe vvv;
    p256_wide_fe r;
    p256_wide_fe x3_numerator;
    p256_wide_fe t;
    p256_wide_fe x3;
    p256_wide_fe y3;
    p256_wide_fe z3;

    // u = Y2 * Z1 - Y1 and v = X2 * Z1 - X1: the slope is u / v.
    p256_wide_fe_mul(&u, &b->y, &a->z);
    p256_wide_fe_sub(&u, &u, &a->y);
    p256_wide_fe_mul(&v, &b->x, &a->z);
    p256_wide_fe_sub(&v, &v, &a->x);
    // uu = u^2, vv = v^2, vvv = v * vv, r = vv * X1.
    p256_wide_fe_sqr(&uu, &u);
    p256_wide_fe_sqr(&vv, &v);
    p256_wide_fe_mul(&vvv, &v, &vv);
    p256_wide_fe_mul(&r, &vv, &a->x);
    // A = uu * Z1 - vvv - 2 * r, X3 = v * A.
    p256_wide_fe_mul(&x3_numerator, &uu, &a->z);
    p256_wide_fe_sub(&x3_numerator, &x3_numerator, &vvv);
    p256_wide_fe_add(&t, &r, &r);
    p256_wide_fe_sub(&x3_numerator, &x3_numerator, &t);
    p256_wide_fe_mul(&x3, &v, &x3_numerator);
    // Y3 = u * (r - A) - vvv * Y1.
    p256_wide_fe_sub(&t, &r, &x3_numerator);
    p256_wide_fe_mul(&y3, &u, &t);
    p256_wide_fe_mul(&t, &vvv, &a->y);
    p256_wide_fe_sub(&y3, &y3, &t);
    // Z3 = vvv * Z1.
    p256_wide_fe_mul(&z3, &vvv, &a->z);

    // o may alias a, so the three coordinates move only now.
    o->x = x3;
    o->y = y3;
    o->z = z3;
}

void p256_wide_point_to_jacobian(p256_wide_jacobian *o, const p256_wide_point *a) {
    p256_wide_fe zz;

    // (X Z : Y Z^2 : Z): x = X Z / Z^2 and y = Y Z^2 / Z^3 are the affine coordinates X / Z
    // and Y / Z, and Z = 0 stays Z = 0.
    p256_wide_fe_mul(&o->x, &a->x, &a->z);
    p256_wide_fe_sqr(&zz, &a->z);
    p256_wide_fe_mul(&o->y, &a->y, &zz);
    o->z = a->z;
}

void p256_wide_point_from_jacobian(p256_wide_point *o, const p256_wide_jacobian *a) {
    p256_wide_fe zz;

    // (X Z : Y : Z^3): X Z / Z^3 = X / Z^2 and Y / Z^3 are the affine coordinates. At Z = 0, X Z
    // and Z^3 are zero, and Y may be zero too, so Y = 1 makes the point at infinity (0 : 1 : 0).
    p256_wide_fe_mul(&o->x, &a->x, &a->z);
    p256_wide_fe_sqr(&zz, &a->z);
    p256_wide_fe_mul(&o->z, &zz, &a->z);
    o->y = a->y;
    p256_wide_fe_cmov(&o->y, &p256_wide_fe_one_mont, p256_wide_fe_zero_mask(&a->z));
}

// The Explicit-Formulas Database's dbl-1986-cc-2 for a = -3, with the database's names in lower
// case. The database writes Z1^2, Y1^2 and Y1^4 inline, and zz, yy and yyyy hold them here. Its
// T is X3. Z3 comes first, where the database computes it last: the next doubling squares it
// first, and with Z3 last each of a key exchange's 253 doublings waited for its product and its
// sum, 4 of 58 µs on the M1 Pro (docs/decisions.md 112). spec/lean/Spec/P256WidePoint.lean
// holds the same steps, one definition per local, and proves what they compute.
void p256_wide_point_double_jacobian(p256_wide_jacobian *o, const p256_wide_jacobian *a) {
    p256_wide_fe zz;
    p256_wide_fe yy;
    p256_wide_fe yyyy;
    p256_wide_fe s;
    p256_wide_fe m;
    p256_wide_fe t;
    p256_wide_fe x3;
    p256_wide_fe y3;
    p256_wide_fe z3;

    // Z3 = 2 * Y1 * Z1.
    p256_wide_fe_mul(&z3, &a->y, &a->z);
    p256_wide_fe_add(&z3, &z3, &z3);
    // zz = Z1^2, and m = 3 * (X1 - zz) * (X1 + zz), the tangent's slope times Z3.
    p256_wide_fe_sqr(&zz, &a->z);
    p256_wide_fe_sub(&t, &a->x, &zz);
    p256_wide_fe_add(&m, &a->x, &zz);
    p256_wide_fe_mul(&m, &t, &m);
    p256_wide_fe_add(&t, &m, &m);
    p256_wide_fe_add(&m, &t, &m);
    // yy = Y1^2, and s = 4 * X1 * yy.
    p256_wide_fe_sqr(&yy, &a->y);
    p256_wide_fe_mul(&s, &a->x, &yy);
    p256_wide_fe_add(&s, &s, &s);
    p256_wide_fe_add(&s, &s, &s);
    // X3 = m^2 - 2 * s.
    p256_wide_fe_sqr(&x3, &m);
    p256_wide_fe_add(&t, &s, &s);
    p256_wide_fe_sub(&x3, &x3, &t);
    // Y3 = m * (s - X3) - 8 * yy^2.
    p256_wide_fe_sub(&t, &s, &x3);
    p256_wide_fe_mul(&y3, &m, &t);
    p256_wide_fe_sqr(&yyyy, &yy);
    p256_wide_fe_add(&yyyy, &yyyy, &yyyy);
    p256_wide_fe_add(&yyyy, &yyyy, &yyyy);
    p256_wide_fe_add(&yyyy, &yyyy, &yyyy);
    p256_wide_fe_sub(&y3, &y3, &yyyy);

    // o may alias a, so the three coordinates move only now.
    o->x = x3;
    o->y = y3;
    o->z = z3;
}

// The Explicit-Formulas Database's add-1998-cmo-2, with the database's names in lower case:
// h = u2 - u1 is zero where the two x are equal, and Z3 = Z1 Z2 h. Z3 comes as soon as h does,
// where the database computes it last, for the doubling's reason: the doubling that follows
// squares it first. spec/lean/Spec/P256WidePoint.lean holds the same steps and proves that
// they add two finite points whose x differ, and p256_wide_mul.c says why p256_wide_mul meets
// that condition.
void p256_wide_point_add_jacobian_incomplete(p256_wide_jacobian *o, const p256_wide_jacobian *a,
                                             const p256_wide_jacobian *b) {
    p256_wide_fe z1z1;
    p256_wide_fe z2z2;
    p256_wide_fe u1;
    p256_wide_fe u2;
    p256_wide_fe s1;
    p256_wide_fe s2;
    p256_wide_fe h;
    p256_wide_fe hh;
    p256_wide_fe hhh;
    p256_wide_fe r;
    p256_wide_fe v;
    p256_wide_fe t;
    p256_wide_fe x3;
    p256_wide_fe y3;
    p256_wide_fe z3;

    // z1z1 = Z1^2, z2z2 = Z2^2, u1 = X1 * z2z2 and u2 = X2 * z1z1: the two x, each times
    // Z1^2 Z2^2.
    p256_wide_fe_sqr(&z1z1, &a->z);
    p256_wide_fe_sqr(&z2z2, &b->z);
    p256_wide_fe_mul(&u1, &a->x, &z2z2);
    p256_wide_fe_mul(&u2, &b->x, &z1z1);
    // s1 = Y1 * Z2 * z2z2 and s2 = Y2 * Z1 * z1z1: the two y, each times Z1^3 Z2^3.
    p256_wide_fe_mul(&s1, &a->y, &b->z);
    p256_wide_fe_mul(&s1, &s1, &z2z2);
    p256_wide_fe_mul(&s2, &b->y, &a->z);
    p256_wide_fe_mul(&s2, &s2, &z1z1);
    // h = u2 - u1, and Z3 = Z1 * Z2 * h.
    p256_wide_fe_sub(&h, &u2, &u1);
    p256_wide_fe_mul(&z3, &a->z, &b->z);
    p256_wide_fe_mul(&z3, &z3, &h);
    // hh = h^2, hhh = h * hh, r = s2 - s1 and v = u1 * hh: r is the slope times Z3.
    p256_wide_fe_sqr(&hh, &h);
    p256_wide_fe_mul(&hhh, &h, &hh);
    p256_wide_fe_sub(&r, &s2, &s1);
    p256_wide_fe_mul(&v, &u1, &hh);
    // X3 = r^2 - hhh - 2 * v.
    p256_wide_fe_sqr(&x3, &r);
    p256_wide_fe_sub(&x3, &x3, &hhh);
    p256_wide_fe_add(&t, &v, &v);
    p256_wide_fe_sub(&x3, &x3, &t);
    // Y3 = r * (v - X3) - s1 * hhh.
    p256_wide_fe_sub(&t, &v, &x3);
    p256_wide_fe_mul(&y3, &r, &t);
    p256_wide_fe_mul(&t, &s1, &hhh);
    p256_wide_fe_sub(&y3, &y3, &t);

    // o may alias a or b, so the three coordinates move only now.
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
