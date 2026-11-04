// P-256 points for a host object's verifier (see p256_wide_verify_point.h
// for the contracts), on p256_wide_field.c's routines. Variable time on
// purpose: every input is public.
//
// The constant-time files compute u1*G and u2*Q apart, on complete
// formulas in homogeneous coordinates, and read every entry of a table to
// keep one. This file is p384_wide_point.c's verifier on P-256's field,
// and differs from them in four ways, each for speed:
//
//   - Points are Jacobian. A doubling is 8 products where the complete
//     doubling is 13, and the cases the formulas do not cover, a point at
//     infinity and a sum of a point with itself or with its negative, are
//     tested for and handled by branches on public values.
//   - u1*G + u2*Q is one pass over both scalars. Each scalar is written as
//     signed digits, zero or odd in [-15, 15], with at least four zeros
//     after every digit that is not zero (the window-5 non-adjacent form),
//     so a scalar adds a point about once in six doublings, and the two
//     scalars share the 256 doublings.
//   - G's digits add entries of row 0 of p256_wide_table.c, the affine
//     odd multiples of G, read by index, through a mixed addition of 11
//     products. Q's digits add multiples of Q this file computes, through
//     the general addition of 16.
//   - A point's affine x is never computed. x is X / Z^2, so x == c exactly
//     when X == c * Z^2, and x mod n == r exactly when x is r, or is r + n
//     and r + n is below p. That saves the inversion of Z.
//
// bin/p256_verify_equiv_test holds the verdict these lead to against
// p256.c's 32-bit arithmetic, and the host Wycheproof test against
// Wycheproof's.
#include "p256_wide_verify_point.h"

#ifdef CH_CPU_RUNTIME

#include <stddef.h>
#include <string.h>

#include "ct.h"
#include "p256_wide_point.h"
#include "p256_wide_table.h"

#define SCALAR_BITS 256
#define WINDOW 5                     // the bits one digit is read from
#define TABLE_LEN 8                  // a point's odd multiples, 1 to 15: 2^(WINDOW - 2) of them
#define DIGITS_LEN (SCALAR_BITS + 1) // a carry out of the top window is one more digit

// SEC 2 secp256r1's group order, least significant word first: the
// constant p256_wide_scalar.c names N0 to N3. tools/p256_wide.py
// recomputes it and stops if a word differs.
static const p256_wide_fe ORDER = {
    {UINT64_C(0xf3b9cac2fc632551), UINT64_C(0xbce6faada7179e84), UINT64_C(0xffffffffffffffff),
     UINT64_C(0xffffffff00000000)}
};

static int fe_is_zero(const p256_wide_fe *a) {
    return p256_wide_fe_zero_mask(a) != 0;
}

void p256_wide_jacobian_from_key(p256_wide_jacobian *o, const p256_point *key) {
    p256_wide_fe_from_portable(&o->x, &key->x);
    p256_wide_fe_from_portable(&o->y, &key->y);
    p256_wide_fe_from_portable(&o->z, &key->z);
}

int p256_wide_jacobian_is_infinity(const p256_wide_jacobian *p) {
    return fe_is_zero(&p->z);
}

// Doubling, a = -3 (EFD dbl-2001-b). It maps the point at infinity to a
// point at infinity: Z = 0 makes Z3 = (Y + Z)^2 - Y^2 - Z^2 zero. P-256 has
// prime order, so no finite point has Y = 0, and twice a finite point is
// finite. o may alias a.
static void point_double(p256_wide_jacobian *o, const p256_wide_jacobian *a) {
    p256_wide_fe delta;
    p256_wide_fe gamma;
    p256_wide_fe beta;
    p256_wide_fe alpha;
    p256_wide_fe t;
    p256_wide_fe t2;
    p256_wide_jacobian r;
    p256_wide_fe_sqr(&delta, &a->z);        // delta = Z^2
    p256_wide_fe_sqr(&gamma, &a->y);        // gamma = Y^2
    p256_wide_fe_mul(&beta, &a->x, &gamma); // beta = X * gamma
    p256_wide_fe_sub(&t, &a->x, &delta);
    p256_wide_fe_add(&t2, &a->x, &delta);
    p256_wide_fe_mul(&alpha, &t, &t2);
    p256_wide_fe_add(&t, &alpha, &alpha);
    p256_wide_fe_add(&alpha, &t, &alpha); // alpha = 3 * (X - delta) * (X + delta)
    p256_wide_fe_sqr(&r.x, &alpha);       // X3 = alpha^2 - 8 * beta
    p256_wide_fe_add(&t, &beta, &beta);
    p256_wide_fe_add(&t, &t, &t); // t = 4 * beta
    p256_wide_fe_add(&t2, &t, &t);
    p256_wide_fe_sub(&r.x, &r.x, &t2);
    p256_wide_fe_add(&r.z, &a->y, &a->z); // Z3 = (Y + Z)^2 - gamma - delta
    p256_wide_fe_sqr(&r.z, &r.z);
    p256_wide_fe_sub(&r.z, &r.z, &gamma);
    p256_wide_fe_sub(&r.z, &r.z, &delta);
    p256_wide_fe_sub(&t, &t, &r.x); // Y3 = alpha * (4 * beta - X3) - 8 * gamma^2
    p256_wide_fe_mul(&r.y, &alpha, &t);
    p256_wide_fe_sqr(&t, &gamma);
    p256_wide_fe_add(&t, &t, &t);
    p256_wide_fe_add(&t, &t, &t);
    p256_wide_fe_add(&t, &t, &t);
    p256_wide_fe_sub(&r.y, &r.y, &t);
    *o = r;
}

// The end of both additions, once h = U2 - U1 is known not to be zero:
// X3 = rr^2 - h^3 - 2 U1 h^2, Y3 = rr (U1 h^2 - X3) - S1 h^3, and Z3 is
// z_product * h, where z_product is Z1 Z2. u1 is U1, s1 is S1 and rr is
// S2 - S1.
static void addition_end(p256_wide_jacobian *o, const p256_wide_fe *u1, const p256_wide_fe *s1,
                         const p256_wide_fe *h, const p256_wide_fe *rr,
                         const p256_wide_fe *z_product) {
    p256_wide_fe hh;
    p256_wide_fe hhh;
    p256_wide_fe v;
    p256_wide_fe t;
    p256_wide_jacobian r;
    p256_wide_fe_sqr(&hh, h);
    p256_wide_fe_mul(&hhh, &hh, h);
    p256_wide_fe_mul(&v, u1, &hh);
    p256_wide_fe_sqr(&r.x, rr);
    p256_wide_fe_sub(&r.x, &r.x, &hhh);
    p256_wide_fe_sub(&r.x, &r.x, &v);
    p256_wide_fe_sub(&r.x, &r.x, &v);
    p256_wide_fe_sub(&t, &v, &r.x);
    p256_wide_fe_mul(&r.y, rr, &t);
    p256_wide_fe_mul(&t, s1, &hhh);
    p256_wide_fe_sub(&r.y, &r.y, &t);
    p256_wide_fe_mul(&r.z, z_product, h);
    *o = r;
}

// General Jacobian addition (EFD add-2007-bl's shape) with the cases it
// does not cover spelled out: either operand at infinity, a == b
// (doubled), and a == -b (infinity). o may alias a.
static void point_add(p256_wide_jacobian *o, const p256_wide_jacobian *a,
                      const p256_wide_jacobian *b) {
    if (p256_wide_jacobian_is_infinity(a)) {
        *o = *b;
        return;
    }
    if (p256_wide_jacobian_is_infinity(b)) {
        *o = *a;
        return;
    }
    p256_wide_fe z1z1;
    p256_wide_fe z2z2;
    p256_wide_fe u1;
    p256_wide_fe u2;
    p256_wide_fe s1;
    p256_wide_fe s2;
    p256_wide_fe h;
    p256_wide_fe rr;
    p256_wide_fe z_product;
    p256_wide_fe_sqr(&z1z1, &a->z);
    p256_wide_fe_sqr(&z2z2, &b->z);
    p256_wide_fe_mul(&u1, &a->x, &z2z2);
    p256_wide_fe_mul(&u2, &b->x, &z1z1);
    p256_wide_fe_mul(&s1, &a->y, &b->z);
    p256_wide_fe_mul(&s1, &s1, &z2z2);
    p256_wide_fe_mul(&s2, &b->y, &a->z);
    p256_wide_fe_mul(&s2, &s2, &z1z1);
    p256_wide_fe_sub(&h, &u2, &u1);
    p256_wide_fe_sub(&rr, &s2, &s1);
    if (fe_is_zero(&h)) {
        if (fe_is_zero(&rr)) {
            point_double(o, a);
        } else {
            memset(o, 0, sizeof *o);
        }
        return;
    }
    p256_wide_fe_mul(&z_product, &a->z, &b->z);
    addition_end(o, &u1, &s1, &h, &rr, &z_product);
}

// Mixed addition of an affine b, Z2 = 1 (EFD madd-2007-bl's shape), with
// the same cases spelled out. o may alias a.
static void point_add_affine(p256_wide_jacobian *o, const p256_wide_jacobian *a,
                             const p256_wide_affine *b) {
    if (p256_wide_jacobian_is_infinity(a)) {
        o->x = b->x;
        o->y = b->y;
        o->z = p256_wide_fe_one_mont;
        return;
    }
    p256_wide_fe z1z1;
    p256_wide_fe u2;
    p256_wide_fe s2;
    p256_wide_fe h;
    p256_wide_fe rr;
    p256_wide_fe_sqr(&z1z1, &a->z);
    p256_wide_fe_mul(&u2, &b->x, &z1z1); // U1 is X1
    p256_wide_fe_mul(&s2, &b->y, &a->z); // S1 is Y1
    p256_wide_fe_mul(&s2, &s2, &z1z1);
    p256_wide_fe_sub(&h, &u2, &a->x);
    p256_wide_fe_sub(&rr, &s2, &a->y);
    if (fe_is_zero(&h)) {
        if (fe_is_zero(&rr)) {
            point_double(o, a);
        } else {
            memset(o, 0, sizeof *o);
        }
        return;
    }
    addition_end(o, &a->x, &a->y, &h, &rr, &a->z);
}

// Bits [pos, pos + count) of k as a number, for pos + count at most 256.
// Shifts and masks stand in for / and %.
static uint32_t scalar_bits(const p256_scalar *k, int pos, int count) {
    uint32_t value = 0;
    for (int i = 0; i < count; i++) {
        int bit = pos + i;
        value |= ((k->word[bit >> 5] >> (bit & 31)) & 1U) << i;
    }
    return value;
}

// Writes k as signed digits: k is the sum of digits[i] * 2^i, each digit is
// zero or odd in [-15, 15], and the four digits above a digit that is not
// zero are zero. Returns the position of the top digit that is not zero,
// plus one; that is 0 for k = 0 and at most DIGITS_LEN.
//
// It walks up from bit 0 with a carry of 0 or 1. Where the bit plus the
// carry is even, the digit is zero and the carry stays as it is. Where it
// is odd, the next five bits plus the carry are an odd value in [1, 31]. A
// value under 16 is the digit. A value over 16 is 32 more than the digit,
// so the digit is that value less 32 and the carry into the bits above the
// five is 1. Either way the other four of the five positions get a zero
// and are passed over. Fewer than five bits are left near the top, and
// there the value is under 16.
static int signed_digits(int8_t digits[DIGITS_LEN], const p256_scalar *k) {
    int len = 0;
    uint32_t carry = 0;
    int passed_over = 0; // positions still to pass over after the last digit
    for (int pos = 0; pos < SCALAR_BITS; pos++) {
        digits[pos] = 0;
        if (passed_over > 0) {
            passed_over--;
            continue;
        }
        if (scalar_bits(k, pos, 1) == carry) {
            continue;
        }
        int width = SCALAR_BITS - pos < WINDOW ? SCALAR_BITS - pos : WINDOW;
        uint32_t value = scalar_bits(k, pos, width) + carry;
        carry = value >> (WINDOW - 1);
        digits[pos] = (int8_t)((int)value - (int)(carry << WINDOW));
        len = pos + 1;
        passed_over = width - 1;
    }
    // A carry out of the top bit is one more digit, of 1.
    digits[SCALAR_BITS] = (int8_t)carry;
    return carry != 0 ? DIGITS_LEN : len;
}

// table[i] = (2i + 1) * p.
static void odd_multiples(p256_wide_jacobian table[TABLE_LEN], const p256_wide_jacobian *p) {
    p256_wide_jacobian twice;
    point_double(&twice, p);
    table[0] = *p;
    for (int i = 1; i < TABLE_LEN; i++) {
        point_add(&table[i], &table[i - 1], &twice);
    }
}

// acc += digit * G, for an odd digit in [-15, 15]: row 0 of the table of
// multiples of G holds (2j + 1) * G at j. The negative of (x, y) is
// (x, -y).
static void add_g_multiple(p256_wide_jacobian *acc, int digit) {
    p256_wide_affine term = p256_wide_table[0][(digit < 0 ? -digit : digit) >> 1];
    if (digit < 0) {
        p256_wide_fe_neg(&term.y, &term.y);
    }
    point_add_affine(acc, acc, &term);
}

// acc += digit * q, for an odd digit in [-15, 15] and the table of q's odd
// multiples. The negative of (X, Y, Z) is (X, -Y, Z).
static void add_q_multiple(p256_wide_jacobian *acc, const p256_wide_jacobian table[TABLE_LEN],
                           int digit) {
    p256_wide_jacobian term = table[(digit < 0 ? -digit : digit) >> 1];
    if (digit < 0) {
        p256_wide_fe_neg(&term.y, &term.y);
    }
    point_add(acc, acc, &term);
}

void p256_wide_jacobian_double_mul(p256_wide_jacobian *o, const p256_scalar *u1,
                                   const p256_scalar *u2, const p256_wide_jacobian *q) {
    p256_wide_jacobian q_table[TABLE_LEN];
    int8_t g_digits[DIGITS_LEN];
    int8_t q_digits[DIGITS_LEN];
    odd_multiples(q_table, q);
    int g_len = signed_digits(g_digits, u1);
    int q_len = signed_digits(q_digits, u2);
    p256_wide_jacobian acc;
    memset(&acc, 0, sizeof acc); // the point at infinity
    for (int i = (g_len > q_len ? g_len : q_len) - 1; i >= 0; i--) {
        point_double(&acc, &acc);
        if (g_digits[i] != 0) {
            add_g_multiple(&acc, g_digits[i]);
        }
        if (q_digits[i] != 0) {
            add_q_multiple(&acc, q_table, q_digits[i]);
        }
    }
    *o = acc;
}

// The scalar's value as a field element, not in the Montgomery domain. A
// scalar below n is below p.
static void fe_from_scalar(p256_wide_fe *o, const p256_scalar *a) {
    for (size_t i = 0; i < P256_WIDE_FE_WORDS; i++) {
        o->word[i] = (uint64_t)a->word[2 * i] | ((uint64_t)a->word[2 * i + 1] << 32);
    }
}

// 1 when the affine x of sum is c, for c below p and zz = Z^2: the test is
// X == c * Z^2, both sides in the Montgomery domain.
static int x_is(const p256_wide_jacobian *sum, const p256_wide_fe *zz, const p256_wide_fe *c) {
    p256_wide_fe scaled;
    p256_wide_fe_to_mont(&scaled, c);
    p256_wide_fe_mul(&scaled, &scaled, zz);
    return p256_wide_fe_equal_mask(&scaled, &sum->x) != 0;
}

// x is below p and p is below 2n, so x mod n is r for two values of x at
// most: r, and r + n when that is below p.
int p256_wide_jacobian_x_is_r(const p256_wide_jacobian *sum, const p256_scalar *r) {
    p256_wide_fe zz;
    p256_wide_fe c;
    p256_wide_fe_sqr(&zz, &sum->z);
    fe_from_scalar(&c, r);
    if (x_is(sum, &zz, &c)) {
        return 1;
    }
    // c = r + n, 128 bits wide at each word so that the carry out of the
    // top word is kept.
    ct_u128 sum_word = 0;
    for (size_t i = 0; i < P256_WIDE_FE_WORDS; i++) {
        sum_word = (ct_u128)c.word[i] + ORDER.word[i] + (uint64_t)(sum_word >> 64);
        c.word[i] = (uint64_t)sum_word;
    }
    if ((uint64_t)(sum_word >> 64) != 0 || p256_wide_fe_reduced_mask(&c) == 0) {
        return 0;
    }
    return x_is(sum, &zz, &c);
}

#endif // CH_CPU_RUNTIME
