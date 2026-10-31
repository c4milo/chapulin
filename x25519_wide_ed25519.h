// Ed25519 verification on the wide field (ed25519_verify.h states the
// contract), included by x25519_wide.c alone, after x25519_wide_edwards.h,
// whose points, doubling and mixed addition it reuses. Every input is
// public, so the code branches on the scalars' bits and on comparisons;
// none of it runs on a secret.
//
// The word bounds of INV-34 hold here as in the ladder: add() and sub()
// take results of mul(), sqr() or unpack(), and every value that would
// otherwise reach one of them out of those bounds goes through reduce(),
// which writes the canonical words below 2^51.
#ifndef CH_X25519_WIDE_ED25519_H
#define CH_X25519_WIDE_ED25519_H

#ifdef CH_DNSSEC

#include <string.h>

#include "ed25519_verify.h"

// d = -121665 / 121666 mod p, the curve constant of edwards25519.
static const fe ED25519_D = {UINT64_C(0x34dca135978a3), UINT64_C(0x1a8283b156ebd),
                             UINT64_C(0x5e7a26001c029), UINT64_C(0x739c663a03cbb),
                             UINT64_C(0x52036cee2b6ff)};
// The square root of -1 mod p, 2^((p - 1) / 4).
static const fe ED25519_SQRT_M1 = {UINT64_C(0x61b274a0ea0b0), UINT64_C(0xd5a5fc8f189d),
                                   UINT64_C(0x7ef5e9cbd0c60), UINT64_C(0x78595a6804c9e),
                                   UINT64_C(0x2b8324804fc1d)};
// L, the order of B, as four little-endian 64-bit words.
static const uint64_t ED25519_L[4] = {UINT64_C(0x5812631a5cf5d3ed), UINT64_C(0x14def9dea2f79cd6), 0,
                                      UINT64_C(0x1000000000000000)};
static const fe FE_ZERO = {0};
static const fe FE_ONE = {1};

// o = the canonical words of a, each below 2^51.
static void reduce(fe o, const fe a) {
    uint8_t bytes[X25519_LEN];
    pack(bytes, a);
    unpack(o, bytes);
}

static int fe_equal(const fe a, const fe b) {
    uint8_t x[X25519_LEN];
    uint8_t y[X25519_LEN];
    pack(x, a);
    pack(y, b);
    return ct_memeq(x, y, X25519_LEN) != 0;
}

// The low bit of a's canonical value, which RFC 8032 calls x's sign.
static int fe_negative(const fe a) {
    uint8_t x[X25519_LEN];
    pack(x, a);
    return x[0] & 1;
}

// o = -a, canonical.
static void negate(fe o, const fe a) {
    fe r;
    reduce(r, a);
    sub(o, FE_ZERO, r);
    reduce(o, o);
}

// o = z^((p - 5) / 8) = z^(2^252 - 3), invert()'s chain to z^(2^250 - 1),
// then two squarings and a product by z.
static void pow_p58(fe o, const fe z) {
    fe z2;
    fe z9;
    fe z11;
    fe z2_5_0;
    fe z2_10_0;
    fe z2_20_0;
    fe z2_50_0;
    fe z2_100_0;
    fe t;
    sqr(z2, z);
    sqr_times(t, z2, 2);
    mul(z9, t, z);
    mul(z11, z9, z2);
    sqr(t, z11);
    mul(z2_5_0, t, z9);
    sqr_times(t, z2_5_0, 5);
    mul(z2_10_0, t, z2_5_0);
    sqr_times(t, z2_10_0, 10);
    mul(z2_20_0, t, z2_10_0);
    sqr_times(t, z2_20_0, 20);
    mul(t, t, z2_20_0);
    sqr_times(t, t, 10);
    mul(z2_50_0, t, z2_10_0);
    sqr_times(t, z2_50_0, 50);
    mul(z2_100_0, t, z2_50_0);
    sqr_times(t, z2_100_0, 100);
    mul(t, t, z2_100_0);
    sqr_times(t, t, 50);
    mul(t, t, z2_50_0); // z^(2^250 - 1)
    sqr_times(t, t, 2); // z^(2^252 - 4)
    mul(o, t, z);       // z^(2^252 - 3)
}

// 1 when the 32 bytes s hold a y at or above p, the encodings RFC 8032
// section 5.1.3 step 1 refuses. Bit 255 is x's sign and takes no part.
static int y_not_canonical(const uint8_t s[X25519_LEN]) {
    if ((s[31] & 0x7f) != 0x7f) {
        return 0;
    }
    for (size_t i = 30; i >= 1; i--) {
        if (s[i] != 0xff) {
            return 0;
        }
    }
    return s[0] >= 0xed;
}

// RFC 8032 section 5.1.3: the point s encodes, as affine x and y with
// canonical words. Returns 0 for an encoding that names no point.
static int decode_point(fe x, fe y, const uint8_t s[X25519_LEN]) {
    if (y_not_canonical(s)) {
        return 0;
    }
    unpack(y, s);
    fe u;
    fe v;
    fe v3;
    fe t;
    sqr(u, y);
    mul(v, u, ED25519_D);
    sub(u, u, FE_ONE); // u = y^2 - 1
    reduce(u, u);
    add(v, v, FE_ONE); // v = d y^2 + 1
    reduce(v, v);
    sqr(v3, v);
    mul(v3, v3, v); // v^3
    sqr(x, v3);
    mul(x, x, v);
    mul(x, x, u); // u v^7
    pow_p58(x, x);
    mul(x, x, v3);
    mul(x, x, u); // u v^3 (u v^7)^((p - 5) / 8)
    sqr(t, x);
    mul(t, t, v); // v x^2
    if (!fe_equal(t, u)) {
        fe minus_u;
        negate(minus_u, u);
        if (!fe_equal(t, minus_u)) {
            return 0;
        }
        mul(x, x, ED25519_SQRT_M1);
    }
    reduce(x, x);
    int sign = s[31] >> 7;
    if (fe_equal(x, FE_ZERO) && sign) {
        return 0;
    }
    if (fe_negative(x) != sign) {
        negate(x, x);
    }
    return 1;
}

// The table form of the affine point (x, y): y + x, y - x and 2 d x y,
// each canonical, which add_entry() adds.
static void to_entry(edwards_entry *o, const fe x, const fe y) {
    add(o->y_plus_x, y, x);
    reduce(o->y_plus_x, o->y_plus_x);
    sub(o->y_minus_x, y, x);
    reduce(o->y_minus_x, o->y_minus_x);
    mul(o->xy2d, x, y);
    mul(o->xy2d, o->xy2d, ED25519_D);
    add(o->xy2d, o->xy2d, o->xy2d);
    reduce(o->xy2d, o->xy2d);
}

static void double_in_place(edwards_point *p) {
    edwards_sum s;
    double_point(&s, p);
    to_extended(p, &s);
}

static void add_in_place(edwards_point *p, const edwards_entry *e) {
    edwards_sum s;
    add_entry(&s, p, e);
    to_extended(p, &s);
}

// 1 when the four little-endian words a are at or above b.
static int at_or_above_l(const uint64_t a[4]) {
    for (size_t i = 4; i-- > 0;) {
        if (a[i] != ED25519_L[i]) {
            return a[i] > ED25519_L[i];
        }
    }
    return 1;
}

static void words_of(uint64_t o[4], const uint8_t b[32]) {
    for (size_t i = 0; i < 4; i++) {
        o[i] = load_le64(b + 8 * i);
    }
}

// o = 2 o + bit, less L when that reaches L: one step of the division
// below. From an o below L it leaves o below L, so a doubling stays below
// 2^254 and o never needs more than one subtraction.
static void reduce_step(uint64_t o[4], uint64_t bit) {
    o[3] = (o[3] << 1) | (o[2] >> 63);
    o[2] = (o[2] << 1) | (o[1] >> 63);
    o[1] = (o[1] << 1) | (o[0] >> 63);
    o[0] = (o[0] << 1) | bit;
    if (at_or_above_l(o)) {
        uint64_t borrow = 0;
        for (size_t i = 0; i < 4; i++) {
            uint64_t d = o[i] - ED25519_L[i] - borrow;
            borrow = (o[i] < ED25519_L[i]) || (o[i] - ED25519_L[i] < borrow);
            o[i] = d;
        }
    }
}

// o = the 512-bit little-endian h mod L, one bit at a time from the top.
static void reduce_mod_l(uint64_t o[4], const uint8_t h[64]) {
    o[0] = o[1] = o[2] = o[3] = 0;
    for (size_t bit = 512; bit-- > 0;) {
        reduce_step(o, (uint64_t)((h[bit >> 3] >> (bit & 7)) & 1));
    }
}

static int bit_of(const uint64_t w[4], size_t i) {
    return (int)((w[i >> 6] >> (i & 63)) & 1);
}

int ed25519_verify_hram(const uint8_t key[32], const uint8_t hram[64], const uint8_t sig[64]) {
    uint64_t s[4];
    words_of(s, sig + 32);
    if (at_or_above_l(s)) {
        return 0;
    }
    fe ax;
    fe ay;
    if (!decode_point(ax, ay, key)) {
        return 0;
    }
    // A small-order A: [8]A is the identity, whose X is 0.
    edwards_point a = {.z = {1}};
    memcpy(a.x, ax, sizeof ax);
    memcpy(a.y, ay, sizeof ay);
    mul(a.t, ax, ay);
    for (int i = 0; i < 3; i++) {
        double_in_place(&a);
    }
    if (fe_equal(a.x, FE_ZERO)) {
        return 0;
    }
    uint64_t h[4];
    reduce_mod_l(h, hram);

    // [S]B + [h](-A), left to right over the 253 bits below L's top.
    edwards_entry b;
    memcpy(&b, X25519_WIDE_TABLE[0][0], sizeof b);
    edwards_entry minus_a;
    fe nx;
    negate(nx, ax);
    to_entry(&minus_a, nx, ay);
    edwards_point acc = {.y = {1}, .z = {1}};
    for (size_t i = 253; i-- > 0;) {
        double_in_place(&acc);
        if (bit_of(s, i)) {
            add_in_place(&acc, &b);
        }
        if (bit_of(h, i)) {
            add_in_place(&acc, &minus_a);
        }
    }
    fe zi;
    fe x;
    fe y;
    invert(zi, acc.z);
    mul(x, acc.x, zi);
    mul(y, acc.y, zi);
    uint8_t r[X25519_LEN];
    pack(r, y);
    r[31] |= (uint8_t)(fe_negative(x) << 7);
    return ct_memeq_public(r, sig, X25519_LEN) != 0;
}

#endif // CH_DNSSEC

#endif
