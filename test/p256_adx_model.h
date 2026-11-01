// A model of p256_adx_field.c's two assembly routines in portable C, on
// ct.h's ct_u128. p256_adx_field.c includes it in their place under
// CH_P256_ADX_MODEL, with -Itest: the CBMC harnesses, the model test and the
// differential build it that way, and no library object does.
// bin/p256_adx_equiv_test includes it beside the assembly build and compares
// the two word for word.
//
// Each step writes the words the assembly writes: the eight words of the
// product, then each round as the assembly runs it, u << 32 and u >> 32 and
// the two words of u * p3 added at words k + 1 to k + 4 with the carry the
// round before left, then the final subtraction of p and the choice by the
// borrow. spec/lean/Spec/P256Adx.lean models the same steps.
#ifndef CH_TEST_P256_ADX_MODEL_H
#define CH_TEST_P256_ADX_MODEL_H

#include <stdint.h>

#include "ct.h"

// p's words, least significant first. p256_wide_field.h names the same four.
#define P256_ADX_MODEL_P0 UINT64_C(0xffffffffffffffff)
#define P256_ADX_MODEL_P1 UINT64_C(0x00000000ffffffff)
#define P256_ADX_MODEL_P2 UINT64_C(0x0000000000000000)
#define P256_ADX_MODEL_P3 UINT64_C(0xffffffff00000001)

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

// Round k of the reduction on t: u = t[k], then u << 32, u >> 32 and the two
// words of u * p3, the high one plus the carry top, added at t[k + 1] to
// t[k + 4]. Returns the carry out of t[k + 4]. The high word of u * p3 is at
// most 2^64 - 2^32 and top is 0 or 1, so their sum does not wrap.
static inline uint64_t model_round(uint64_t t[8], int k, uint64_t top) {
    uint64_t u = t[k];
    ct_u128 multiple = ct_mul128(u, P256_ADX_MODEL_P3);
    const uint64_t addend[4] = {u << 32, u >> 32, (uint64_t)multiple,
                                (uint64_t)(multiple >> 64) + top};
    ct_u128 carry = 0;
    for (int i = 0; i < 4; i++) {
        carry += (ct_u128)t[k + 1 + i] + addend[i];
        t[k + 1 + i] = (uint64_t)carry;
        carry >>= 64;
    }
    return (uint64_t)carry;
}

// o = (top : t[7] : t[6] : t[5] : t[4]) less p where that does not borrow,
// and t[4] to t[7] where it does. Each word's difference is 2^64 + t - p -
// borrow in 128 bits, which is never negative: its low word is the
// difference word, and bit 64 is clear exactly when the word borrowed.
static inline void model_reduce_once(uint64_t o[4], const uint64_t t[8], uint64_t top) {
    static const uint64_t p[4] = {P256_ADX_MODEL_P0, P256_ADX_MODEL_P1, P256_ADX_MODEL_P2,
                                  P256_ADX_MODEL_P3};
    uint64_t r[4];
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        ct_u128 d = ((ct_u128)1 << 64) + t[4 + i] - p[i] - borrow;
        r[i] = (uint64_t)d;
        borrow = 1 - (uint64_t)(d >> 64);
    }
    // The top word less the borrow, as the assembly's last SBB: it borrows
    // exactly when top is 0 and the four words borrowed. The mask is that
    // bit times UINT64_MAX, so no step wraps.
    uint64_t keep = UINT64_MAX * (borrow & (top ^ 1U) & 1U);
    for (int i = 0; i < 4; i++) {
        o[i] = (t[4 + i] & keep) | (r[i] & ~keep);
    }
}

// The four rounds and the final subtraction, as both assembly routines end.
static inline void model_reduce(uint64_t o[4], uint64_t t[8]) {
    uint64_t top = 0;
    for (int k = 0; k < 4; k++) {
        top = model_round(t, k, top);
    }
    model_reduce_once(o, t, top);
}

// o = a * b / 2^256 mod p. o may be a or b.
static inline void p256_adx_mul_mont(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t t[8];
    model_product(t, a, b);
    model_reduce(o, t);
}

// o = a * a / 2^256 mod p. o may be a.
static inline void p256_adx_sqr_mont(uint64_t o[4], const uint64_t a[4]) {
    uint64_t t[8];
    model_product(t, a, a);
    model_reduce(o, t);
}

#endif
