// A model of x25519_adx.c's five assembly operations in portable C, on
// ct.h's ct_u128. x25519_adx.c includes it in their place under
// CH_X25519_ADX_MODEL, with -Itest: the CBMC harnesses, the model test and
// the equivalence test build it that way, and no library object does.
//
// Each function writes the four words its assembly writes, not only a value
// congruent mod p, so bin/x25519_adx_equiv_test can compare them word for
// word: the same product, the same fold of its high half times 38, the same
// carry folded twice.
#ifndef CH_TEST_X25519_ADX_MODEL_H
#define CH_TEST_X25519_ADX_MODEL_H

#include <stdint.h>

#include "ct.h"

// o += 38 * the carry c, word by word, and the carry out.
static inline uint64_t model_fold(uint64_t o[4], uint64_t c) {
    ct_u128 t = (ct_u128)o[0] + ct_mul128(c, 38);
    o[0] = (uint64_t)t;
    for (int i = 1; i < 4; i++) {
        t = (ct_u128)o[i] + (uint64_t)(t >> 64);
        o[i] = (uint64_t)t;
    }
    return (uint64_t)(t >> 64);
}

// The eight words of a product to four, as adx_mul's last step does: the low
// four plus 38 times the high four, then the carry out of that, times 38, then
// 38 once more if that carried.
static inline void model_reduce(fe o, const uint64_t t[8]) {
    uint64_t r[4];
    ct_u128 acc = 0;
    for (int i = 0; i < 4; i++) {
        acc += (ct_u128)t[i] + ct_mul128(t[i + 4], 38);
        r[i] = (uint64_t)acc;
        acc >>= 64;
    }
    uint64_t carry = model_fold(r, (uint64_t)acc);
    r[0] += carry * 38;
    for (int i = 0; i < 4; i++) {
        o[i] = r[i];
    }
}

// The eight words of a * b.
static inline void model_product(uint64_t t[8], const uint64_t a[4], const uint64_t b[4]) {
    for (int i = 0; i < 8; i++) {
        t[i] = 0;
    }
    for (int i = 0; i < 4; i++) {
        ct_u128 carry = 0;
        for (int j = 0; j < 4; j++) {
            carry += (ct_u128)t[i + j] + ct_mul128(a[j], b[i]);
            t[i + j] = (uint64_t)carry;
            carry >>= 64;
        }
        t[i + 4] = (uint64_t)carry;
    }
}

static inline void adx_mul(fe o, const fe a, const fe b) {
    uint64_t t[8];
    model_product(t, a, b);
    model_reduce(o, t);
}

static inline void adx_sqr(fe o, const fe a) {
    uint64_t t[8];
    model_product(t, a, a);
    model_reduce(o, t);
}

static inline void adx_add(fe o, const fe a, const fe b) {
    uint64_t r[4];
    ct_u128 t = 0;
    for (int i = 0; i < 4; i++) {
        t += (ct_u128)a[i] + b[i];
        r[i] = (uint64_t)t;
        t >>= 64;
    }
    uint64_t carry = model_fold(r, (uint64_t)t);
    r[0] += carry * 38;
    for (int i = 0; i < 4; i++) {
        o[i] = r[i];
    }
}

static inline void adx_sub(fe o, const fe a, const fe b) {
    uint64_t r[4];
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t d = a[i] - b[i];
        uint64_t out = (a[i] < b[i]) | (d < borrow);
        r[i] = d - borrow;
        borrow = out;
    }
    uint64_t c = borrow * 38;
    for (int i = 0; i < 4; i++) {
        uint64_t d = r[i] - c;
        c = r[i] < c;
        r[i] = d;
    }
    r[0] -= c * 38;
    for (int i = 0; i < 4; i++) {
        o[i] = r[i];
    }
}

static inline void adx_mul_a24(fe o, const fe a) {
    uint64_t r[4];
    ct_u128 t = 0;
    for (int i = 0; i < 4; i++) {
        t += ct_mul128(a[i], 121666);
        r[i] = (uint64_t)t;
        t >>= 64;
    }
    uint64_t carry = model_fold(r, (uint64_t)t);
    r[0] += carry * 38;
    for (int i = 0; i < 4; i++) {
        o[i] = r[i];
    }
}

#endif
