// P-384 points for a host object's verifier (p384_wide_point.h), on
// p384_wide_field.c's six 64-bit words. Variable time on purpose — every
// input is public (see p384.h).
//
// The points and the group law are p384.c's, formula for formula. Three
// things differ, each for speed, and bin/p384_equiv_test holds the
// verdict they lead to against p384.c's:
//
//   - A coordinate stays in the Montgomery domain from the key's decoding
//     to the last comparison, so a field product is one Montgomery
//     multiplication where p384.c runs two.
//   - u1*G + u2*Q is one pass over both scalars. Each scalar is written
//     as signed digits, zero or odd in [-15, 15], with at least four
//     zeros after every digit that is not zero (the window-5 non-adjacent
//     form). A scalar then adds a point about once in six doublings, from
//     a table of that point's eight odd multiples.
//   - A point's affine x is never computed. x is X / Z^2, so x == c
//     exactly when X == c * Z^2, and x mod n == r exactly when x is r, or
//     is r + n and r + n is below p. That saves the inversion of Z.
#include "p384_wide_point.h"

#ifdef CH_CPU_RUNTIME

#include <string.h>

#define WORDS P384_WIDE_WORDS
#define SCALAR_BITS 384
#define WINDOW 5                     // the bits one digit is read from
#define TABLE_LEN 8                  // a point's odd multiples, 1 to 15: 2^(WINDOW - 2) of them
#define DIGITS_LEN (SCALAR_BITS + 1) // a carry out of the top window is one more digit

// SEC 2 curve constants, printed by test/gen_p384_constants.py after it
// checks them against openssl. a = p - 3, so the a = -3 doubling
// formula applies unchanged.
static const uint64_t B[WORDS] = {0x2a85c8edd3ec2aef, 0xc656398d8a2ed19d, 0x0314088f5013875a,
                                  0x181d9c6efe814112, 0x988e056be3f82d19, 0xb3312fa7e23ee7e4};

static const uint64_t GX[WORDS] = {0x3a545e3872760ab7, 0x5502f25dbf55296c, 0x59f741e082542a38,
                                   0x6e1d3b628ba79b98, 0x8eb1c71ef320ad74, 0xaa87ca22be8b0537};

static const uint64_t GY[WORDS] = {0x7a431d7c90ea0e5f, 0x0a60b1ce1d7e819d, 0xe9da3113b5f0b8c0,
                                   0xf8f41dbd289a147c, 0x5d9e98bf9292dc29, 0x3617de4a96262c6f};

static const uint64_t ONE[WORDS] = {1};

// o = a * 2^384 mod p, for a below p.
static void to_montgomery(uint64_t o[WORDS], const uint64_t a[WORDS]) {
    p384_wide_mont_mul(o, a, p384_wide_modp.r2, &p384_wide_modp);
}

// Doubling, a = -3 (EFD dbl-2001-b). Maps infinity to infinity: z == 0
// forces z3 == 0.
static void point_double(p384_wide_point *o, const p384_wide_point *a) {
    uint64_t delta[WORDS];
    uint64_t gamma[WORDS];
    uint64_t beta[WORDS];
    uint64_t alpha[WORDS];
    uint64_t t[WORDS];
    uint64_t t2[WORDS];
    p384_wide_point r;
    p384_wide_mont_mul(delta, a->z, a->z, &p384_wide_modp); // delta = Z^2
    p384_wide_mont_mul(gamma, a->y, a->y, &p384_wide_modp); // gamma = Y^2
    p384_wide_mont_mul(beta, a->x, gamma, &p384_wide_modp); // beta = X*gamma
    p384_wide_mod_sub(t, a->x, delta, &p384_wide_modp);
    p384_wide_mod_add(t2, a->x, delta, &p384_wide_modp);
    p384_wide_mont_mul(alpha, t, t2, &p384_wide_modp); // alpha = 3*(X-delta)*(X+delta)
    p384_wide_mod_add(t, alpha, alpha, &p384_wide_modp);
    p384_wide_mod_add(alpha, t, alpha, &p384_wide_modp);
    p384_wide_mont_mul(r.x, alpha, alpha, &p384_wide_modp); // X3 = alpha^2 - 8*beta
    p384_wide_mod_add(t, beta, beta, &p384_wide_modp);
    p384_wide_mod_add(t, t, t, &p384_wide_modp); // t = 4*beta
    p384_wide_mod_add(t2, t, t, &p384_wide_modp);
    p384_wide_mod_sub(r.x, r.x, t2, &p384_wide_modp);
    p384_wide_mod_add(r.z, a->y, a->z, &p384_wide_modp); // Z3 = (Y+Z)^2 - gamma - delta
    p384_wide_mont_mul(r.z, r.z, r.z, &p384_wide_modp);
    p384_wide_mod_sub(r.z, r.z, gamma, &p384_wide_modp);
    p384_wide_mod_sub(r.z, r.z, delta, &p384_wide_modp);
    p384_wide_mod_sub(t, t, r.x, &p384_wide_modp); // Y3 = alpha*(4*beta - X3) - 8*gamma^2
    p384_wide_mont_mul(r.y, alpha, t, &p384_wide_modp);
    p384_wide_mont_mul(t, gamma, gamma, &p384_wide_modp);
    p384_wide_mod_add(t, t, t, &p384_wide_modp);
    p384_wide_mod_add(t, t, t, &p384_wide_modp);
    p384_wide_mod_add(t, t, t, &p384_wide_modp);
    p384_wide_mod_sub(r.y, r.y, t, &p384_wide_modp);
    *o = r;
}

// General Jacobian addition (EFD add-2007-bl shape) with the exceptional
// cases spelled out: either operand at infinity, P == Q (double), and
// P == -Q (infinity). o may alias a.
static void point_add(p384_wide_point *o, const p384_wide_point *a, const p384_wide_point *b) {
    if (p384_wide_is_zero(a->z)) {
        *o = *b;
        return;
    }
    if (p384_wide_is_zero(b->z)) {
        *o = *a;
        return;
    }
    uint64_t z1z1[WORDS];
    uint64_t z2z2[WORDS];
    uint64_t u1[WORDS];
    uint64_t u2[WORDS];
    uint64_t s1[WORDS];
    uint64_t s2[WORDS];
    uint64_t h[WORDS];
    uint64_t rr[WORDS];
    p384_wide_mont_mul(z1z1, a->z, a->z, &p384_wide_modp);
    p384_wide_mont_mul(z2z2, b->z, b->z, &p384_wide_modp);
    p384_wide_mont_mul(u1, a->x, z2z2, &p384_wide_modp);
    p384_wide_mont_mul(u2, b->x, z1z1, &p384_wide_modp);
    p384_wide_mont_mul(s1, a->y, b->z, &p384_wide_modp);
    p384_wide_mont_mul(s1, s1, z2z2, &p384_wide_modp);
    p384_wide_mont_mul(s2, b->y, a->z, &p384_wide_modp);
    p384_wide_mont_mul(s2, s2, z1z1, &p384_wide_modp);
    p384_wide_mod_sub(h, u2, u1, &p384_wide_modp);
    p384_wide_mod_sub(rr, s2, s1, &p384_wide_modp);
    if (p384_wide_is_zero(h)) {
        if (p384_wide_is_zero(rr)) {
            point_double(o, a);
        } else {
            memset(o, 0, sizeof *o);
        }
        return;
    }
    uint64_t hh[WORDS];
    uint64_t hhh[WORDS];
    uint64_t v[WORDS];
    uint64_t t[WORDS];
    p384_wide_point r;
    p384_wide_mont_mul(hh, h, h, &p384_wide_modp);
    p384_wide_mont_mul(hhh, hh, h, &p384_wide_modp);
    p384_wide_mont_mul(v, u1, hh, &p384_wide_modp);
    p384_wide_mont_mul(r.x, rr, rr, &p384_wide_modp); // X3 = r^2 - h^3 - 2*u1*h^2
    p384_wide_mod_sub(r.x, r.x, hhh, &p384_wide_modp);
    p384_wide_mod_sub(r.x, r.x, v, &p384_wide_modp);
    p384_wide_mod_sub(r.x, r.x, v, &p384_wide_modp);
    p384_wide_mod_sub(t, v, r.x, &p384_wide_modp); // Y3 = r*(u1*h^2 - X3) - s1*h^3
    p384_wide_mont_mul(r.y, rr, t, &p384_wide_modp);
    p384_wide_mont_mul(t, s1, hhh, &p384_wide_modp);
    p384_wide_mod_sub(r.y, r.y, t, &p384_wide_modp);
    p384_wide_mont_mul(r.z, a->z, b->z, &p384_wide_modp); // Z3 = Z1*Z2*h
    p384_wide_mont_mul(r.z, r.z, h, &p384_wide_modp);
    *o = r;
}

// y^2 == x^3 - 3x + b mod p; inputs below p and in the Montgomery domain.
static int on_curve(const uint64_t x[WORDS], const uint64_t y[WORDS]) {
    uint64_t b[WORDS];
    uint64_t lhs[WORDS];
    uint64_t rhs[WORDS];
    uint64_t t[WORDS];
    to_montgomery(b, B);
    p384_wide_mont_mul(lhs, y, y, &p384_wide_modp);
    p384_wide_mont_mul(t, x, x, &p384_wide_modp);
    p384_wide_mont_mul(rhs, t, x, &p384_wide_modp);
    p384_wide_mod_sub(rhs, rhs, x, &p384_wide_modp);
    p384_wide_mod_sub(rhs, rhs, x, &p384_wide_modp);
    p384_wide_mod_sub(rhs, rhs, x, &p384_wide_modp);
    p384_wide_mod_add(rhs, rhs, b, &p384_wide_modp);
    return p384_wide_compare(lhs, rhs) == 0;
}

// Bits [pos, pos + count) of k as a number, for pos + count at most 384.
static uint32_t scalar_bits(const uint64_t k[WORDS], int pos, int count) {
    uint32_t value = 0;
    for (int i = 0; i < count; i++) {
        int bit = pos + i;
        value |= (uint32_t)((k[bit / 64] >> (bit % 64)) & 1) << i;
    }
    return value;
}

// Writes k as signed digits: k is the sum of digits[i] * 2^i, each digit
// is zero or odd in [-15, 15], and the four digits above a digit that is
// not zero are zero. Returns the position of the top digit that is not
// zero, plus one; that is 0 for k = 0 and at most DIGITS_LEN.
//
// It walks up from bit 0 with a carry of 0 or 1. Where the bit plus the
// carry is even, the digit is zero and the carry stays as it is. Where it
// is odd, the next five bits plus the carry are an odd value in [1, 31].
// A value under 16 is the digit. A value over 16 is 32 more than the
// digit, so the digit is that value less 32 and the carry into the bits
// above the five is 1. Either way the other four of the five positions
// get a zero and are passed over. Fewer than five bits are left near the
// top, and there the value is under 16.
static int signed_digits(int8_t digits[DIGITS_LEN], const uint64_t k[WORDS]) {
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
static void odd_multiples(p384_wide_point table[TABLE_LEN], const p384_wide_point *p) {
    p384_wide_point twice;
    point_double(&twice, p);
    table[0] = *p;
    for (int i = 1; i < TABLE_LEN; i++) {
        point_add(&table[i], &table[i - 1], &twice);
    }
}

// acc += digit * p, for an odd digit in [-15, 15] and the table of p's
// odd multiples. The negative of (x, y, z) is (x, -y, z).
static void add_multiple(p384_wide_point *acc, const p384_wide_point table[TABLE_LEN], int digit) {
    static const uint64_t zero[WORDS] = {0};
    p384_wide_point term = table[(digit < 0 ? -digit : digit) / 2];
    if (digit < 0) {
        p384_wide_mod_sub(term.y, zero, term.y, &p384_wide_modp);
    }
    point_add(acc, acc, &term);
}

// One pass down both scalars' digits.
void p384_wide_double_mul(p384_wide_point *o, const uint64_t u1[P384_WIDE_WORDS],
                          const uint64_t u2[P384_WIDE_WORDS], const p384_wide_point *q) {
    p384_wide_point g;
    p384_wide_point g_table[TABLE_LEN];
    p384_wide_point q_table[TABLE_LEN];
    int8_t g_digits[DIGITS_LEN];
    int8_t q_digits[DIGITS_LEN];
    to_montgomery(g.x, GX);
    to_montgomery(g.y, GY);
    to_montgomery(g.z, ONE);
    odd_multiples(g_table, &g);
    odd_multiples(q_table, q);
    int g_len = signed_digits(g_digits, u1);
    int q_len = signed_digits(q_digits, u2);
    p384_wide_point acc;
    memset(&acc, 0, sizeof acc); // infinity
    for (int i = (g_len > q_len ? g_len : q_len) - 1; i >= 0; i--) {
        point_double(&acc, &acc);
        if (g_digits[i] != 0) {
            add_multiple(&acc, g_table, g_digits[i]);
        }
        if (q_digits[i] != 0) {
            add_multiple(&acc, q_table, q_digits[i]);
        }
    }
    *o = acc;
}

// Writes the key as a p384_wide_point and returns 1, or returns 0 for a coordinate
// at or above p or a p384_wide_point off the curve. Infinity has no X||Y encoding,
// so on-curve suffices.
int p384_wide_point_decode(p384_wide_point *q, const uint8_t pub[P384_PUB_LEN]) {
    uint64_t x[WORDS];
    uint64_t y[WORDS];
    p384_wide_from_bytes(x, pub);
    p384_wide_from_bytes(y, pub + P384_LEN);
    if (p384_wide_compare(x, p384_wide_modp.m) >= 0 ||
        p384_wide_compare(y, p384_wide_modp.m) >= 0) {
        return 0;
    }
    to_montgomery(q->x, x);
    to_montgomery(q->y, y);
    to_montgomery(q->z, ONE);
    return on_curve(q->x, q->y);
}

// 1 when the affine x of sum is c, for c below p and zz = Z^2: the test
// is X == c * Z^2, both sides in the Montgomery domain.
static int x_is(const p384_wide_point *sum, const uint64_t zz[WORDS], const uint64_t c[WORDS]) {
    uint64_t scaled[WORDS];
    to_montgomery(scaled, c);
    p384_wide_mont_mul(scaled, scaled, zz, &p384_wide_modp);
    return p384_wide_compare(scaled, sum->x) == 0;
}

int p384_wide_point_is_infinity(const p384_wide_point *p) {
    return p384_wide_is_zero(p->z);
}

// x is below p and p is below 2n, so x mod n is r for two values of x at
// most: r, and r + n when that is below p.
int p384_wide_point_x_is_r(const p384_wide_point *sum, const uint64_t r[P384_WIDE_WORDS]) {
    uint64_t zz[WORDS];
    uint64_t r_plus_n[WORDS];
    p384_wide_mont_mul(zz, sum->z, sum->z, &p384_wide_modp);
    if (x_is(sum, zz, r)) {
        return 1;
    }
    if (p384_wide_add_raw(r_plus_n, r, p384_wide_modn.m) != 0 ||
        p384_wide_compare(r_plus_n, p384_wide_modp.m) >= 0) {
        return 0;
    }
    return x_is(sum, zz, r_plus_n);
}

#endif // CH_CPU_RUNTIME
