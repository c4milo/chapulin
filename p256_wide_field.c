// The wide P-256 field (see p256_wide_field.h for the contracts). Elements are four
// little-endian uint64 limbs. Multiplication is the 512-bit product, four rows of
// p256_wide_limb.h's p256_wide_mul_row, and then four rounds of Montgomery reduction, which for
// this prime are shifts and adds with no product. Every carry chain is written out limb by
// limb, with no loop over limbs and no array of them, so that gcc keeps the limbs in registers
// as clang does (docs/performance.md, the pitfalls table).
#include "p256_wide_field.h"

#ifdef CH_CPU_RUNTIME

#include <stddef.h>

#include "ct.h"
#include "p256_wide_limb.h"

// SEC 2 secp256r1's field prime, least significant limb first. The same prime is
// p256_field.c's P, in limbs half as wide. tools/p256_wide.py recomputes it and
// every constant derived from it below and stops if a limb differs.
#define P0 UINT64_C(0xffffffffffffffff)
#define P1 UINT64_C(0x00000000ffffffff)
#define P2 UINT64_C(0x0000000000000000)
#define P3 UINT64_C(0xffffffff00000001)

// 2^512 mod p: multiplying by it enters the Montgomery domain.
static const p256_wide_fe RR = {
    {UINT64_C(0x0000000000000003), UINT64_C(0xfffffffbffffffff), UINT64_C(0xfffffffffffffffe),
     UINT64_C(0x00000004fffffffd)}
};
// 2^256 mod p, which is 2^256 - p.
const p256_wide_fe p256_wide_fe_one_mont = {
    {UINT64_C(0x0000000000000001), UINT64_C(0xffffffff00000000), UINT64_C(0xffffffffffffffff),
     UINT64_C(0x00000000fffffffe)}
};
static const p256_wide_fe ONE = {
    {1, 0, 0, 0}
};
static const p256_wide_fe ZERO = {
    {0, 0, 0, 0}
};

// o = (high : t3 : t2 : t1 : t0) - p when that 257-bit value is at or above p, o = t otherwise.
// high is 0 or 1: a sum of two elements below p carries at most one bit past the four limbs,
// and so does each round of reduce() below (proof/p256_wide_field_harness.c).
static inline void reduce_once(uint64_t o[P256_WIDE_FE_LIMBS], uint64_t t0, uint64_t t1,
                               uint64_t t2, uint64_t t3, uint64_t high) {
    uint64_t borrow = 0;
    uint64_t r0 = p256_wide_sub_borrow(&borrow, t0, P0);
    uint64_t r1 = p256_wide_sub_borrow(&borrow, t1, P1);
    uint64_t r2 = p256_wide_sub_borrow(&borrow, t2, P2);
    uint64_t r3 = p256_wide_sub_borrow(&borrow, t3, P3);
    // high : t is below p exactly when high is 0 and the subtraction borrowed out.
    uint64_t keep = p256_wide_mask(borrow & (high ^ 1U));
    o[0] = (t0 & keep) | (r0 & ~keep);
    o[1] = (t1 & keep) | (r1 & ~keep);
    o[2] = (t2 & keep) | (r2 & ~keep);
    o[3] = (t3 & keep) | (r3 & ~keep);
}

// One round of Montgomery reduction on the five limbs (*t4 : *t3 : *t2 : *t1 : u). It adds
// u * p, which makes the low limb zero, drops that limb, and returns the carry out of *t4, 0
// or 1. -p^-1 mod 2^64 is 1, because p's low limb is 2^64 - 1, so the multiplier is u itself,
// and u * (p + 1) / 2^64 is u * (2^192 - 2^160 + 2^128 + 2^32): shifted copies of u, and no
// product. top is the carry the round before returned, which belongs in *t4.
static inline uint64_t reduce_round(uint64_t u, uint64_t *t1, uint64_t *t2, uint64_t *t3,
                                    uint64_t *t4, uint64_t top) {
    // u * (2^64 - 2^32 + 1), the multiple of p's top limb: (u : u) less (u >> 32 : u << 32).
    // Its high limb is at most 2^64 - 2^32, so top fits beside it.
    uint64_t borrow = 0;
    uint64_t multiple_low = p256_wide_sub_borrow(&borrow, u, u << 32);
    uint64_t multiple_high = p256_wide_sub_borrow(&borrow, u, u >> 32);
    uint64_t carry = 0;
    *t1 = p256_wide_add_carry(&carry, *t1, u << 32);
    *t2 = p256_wide_add_carry(&carry, *t2, u >> 32);
    *t3 = p256_wide_add_carry(&carry, *t3, multiple_low);
    *t4 = p256_wide_add_carry(&carry, *t4, multiple_high + top);
    return carry;
}

// o = (t7 : ... : t0) / 2^256 mod p, for any eight limbs. Four rounds leave a value below
// 2^256 + p in (high : t7 : t6 : t5 : t4), so one conditional subtraction lands it below
// 2^256, and below p when the eight limbs are a product of two elements below p.
static void reduce(uint64_t o[P256_WIDE_FE_LIMBS], uint64_t t0, uint64_t t1, uint64_t t2,
                   uint64_t t3, uint64_t t4, uint64_t t5, uint64_t t6, uint64_t t7) {
    uint64_t high = reduce_round(t0, &t1, &t2, &t3, &t4, 0);
    high = reduce_round(t1, &t2, &t3, &t4, &t5, high);
    high = reduce_round(t2, &t3, &t4, &t5, &t6, high);
    high = reduce_round(t3, &t4, &t5, &t6, &t7, high);
    reduce_once(o, t4, t5, t6, t7, high);
}

void p256_wide_fe_from_portable(p256_wide_fe *o, const p256_fe *a) {
    for (size_t i = 0; i < P256_WIDE_FE_LIMBS; i++) {
        o->limb[i] = (uint64_t)a->limb[2 * i] | ((uint64_t)a->limb[2 * i + 1] << 32);
    }
}

void p256_wide_fe_to_portable(p256_fe *o, const p256_wide_fe *a) {
    for (size_t i = 0; i < P256_WIDE_FE_LIMBS; i++) {
        o->limb[2 * i] = (uint32_t)a->limb[i];
        o->limb[2 * i + 1] = (uint32_t)(a->limb[i] >> 32);
    }
}

void p256_wide_fe_from_bytes(p256_wide_fe *o, const uint8_t in[P256_FE_LEN]) {
    for (size_t i = 0; i < P256_WIDE_FE_LIMBS; i++) {
        const uint8_t *word = in + P256_FE_LEN - 8 * (i + 1);
        uint64_t limb = 0;
        for (size_t j = 0; j < 8; j++) {
            limb = (limb << 8) | word[j];
        }
        o->limb[i] = limb;
    }
}

void p256_wide_fe_to_bytes(uint8_t out[P256_FE_LEN], const p256_wide_fe *a) {
    for (size_t i = 0; i < P256_WIDE_FE_LIMBS; i++) {
        uint8_t *word = out + P256_FE_LEN - 8 * (i + 1);
        for (size_t j = 0; j < 8; j++) {
            word[j] = (uint8_t)(a->limb[i] >> (56 - 8 * j));
        }
    }
}

uint64_t p256_wide_fe_reduced_mask(const p256_wide_fe *a) {
    uint64_t borrow = 0;
    (void)p256_wide_sub_borrow(&borrow, a->limb[0], P0);
    (void)p256_wide_sub_borrow(&borrow, a->limb[1], P1);
    (void)p256_wide_sub_borrow(&borrow, a->limb[2], P2);
    (void)p256_wide_sub_borrow(&borrow, a->limb[3], P3);
    return p256_wide_mask(borrow);
}

// All ones when v is zero, zero otherwise: 0 - v borrows exactly when v is nonzero.
static uint64_t zero_mask_word(uint64_t v) {
    uint64_t borrow = 0;
    (void)p256_wide_sub_borrow(&borrow, 0, v);
    return ~p256_wide_mask(borrow);
}

uint64_t p256_wide_fe_zero_mask(const p256_wide_fe *a) {
    return zero_mask_word(a->limb[0] | a->limb[1] | a->limb[2] | a->limb[3]);
}

uint64_t p256_wide_fe_equal_mask(const p256_wide_fe *a, const p256_wide_fe *b) {
    return zero_mask_word((a->limb[0] ^ b->limb[0]) | (a->limb[1] ^ b->limb[1]) |
                          (a->limb[2] ^ b->limb[2]) | (a->limb[3] ^ b->limb[3]));
}

void p256_wide_fe_cmov(p256_wide_fe *o, const p256_wide_fe *a, uint64_t mask) {
    o->limb[0] = (a->limb[0] & mask) | (o->limb[0] & ~mask);
    o->limb[1] = (a->limb[1] & mask) | (o->limb[1] & ~mask);
    o->limb[2] = (a->limb[2] & mask) | (o->limb[2] & ~mask);
    o->limb[3] = (a->limb[3] & mask) | (o->limb[3] & ~mask);
}

void p256_wide_fe_cswap(p256_wide_fe *a, p256_wide_fe *b, uint64_t mask) {
    for (size_t i = 0; i < P256_WIDE_FE_LIMBS; i++) {
        uint64_t exchange = (a->limb[i] ^ b->limb[i]) & mask;
        a->limb[i] ^= exchange;
        b->limb[i] ^= exchange;
    }
}

void p256_wide_fe_add(p256_wide_fe *o, const p256_wide_fe *a, const p256_wide_fe *b) {
    uint64_t carry = 0;
    uint64_t s0 = p256_wide_add_carry(&carry, a->limb[0], b->limb[0]);
    uint64_t s1 = p256_wide_add_carry(&carry, a->limb[1], b->limb[1]);
    uint64_t s2 = p256_wide_add_carry(&carry, a->limb[2], b->limb[2]);
    uint64_t s3 = p256_wide_add_carry(&carry, a->limb[3], b->limb[3]);
    reduce_once(o->limb, s0, s1, s2, s3, carry);
}

void p256_wide_fe_sub(p256_wide_fe *o, const p256_wide_fe *a, const p256_wide_fe *b) {
    uint64_t borrow = 0;
    uint64_t d0 = p256_wide_sub_borrow(&borrow, a->limb[0], b->limb[0]);
    uint64_t d1 = p256_wide_sub_borrow(&borrow, a->limb[1], b->limb[1]);
    uint64_t d2 = p256_wide_sub_borrow(&borrow, a->limb[2], b->limb[2]);
    uint64_t d3 = p256_wide_sub_borrow(&borrow, a->limb[3], b->limb[3]);
    // a < b wrapped the difference by 2^256, and adding p once brings it back into [0, p),
    // because both inputs are below p. The carry out of that sum is the 2^256 the wrap took.
    uint64_t wrapped = p256_wide_mask(borrow);
    uint64_t carry = 0;
    o->limb[0] = p256_wide_add_carry(&carry, d0, P0 & wrapped);
    o->limb[1] = p256_wide_add_carry(&carry, d1, P1 & wrapped);
    o->limb[2] = p256_wide_add_carry(&carry, d2, P2 & wrapped);
    o->limb[3] = p256_wide_add_carry(&carry, d3, P3 & wrapped);
}

void p256_wide_fe_neg(p256_wide_fe *o, const p256_wide_fe *a) {
    // 0 - a is p - a for every element but zero, and zero for zero.
    p256_wide_fe_sub(o, &ZERO, a);
}

void p256_wide_fe_mul(p256_wide_fe *o, const p256_wide_fe *a, const p256_wide_fe *b) {
    uint64_t b0 = b->limb[0];
    uint64_t b1 = b->limb[1];
    uint64_t b2 = b->limb[2];
    uint64_t b3 = b->limb[3];
    uint64_t t0 = 0;
    uint64_t t1 = 0;
    uint64_t t2 = 0;
    uint64_t t3 = 0;
    uint64_t t4 = p256_wide_mul_row(&t0, &t1, &t2, &t3, a->limb[0], b0, b1, b2, b3);
    uint64_t t5 = p256_wide_mul_row(&t1, &t2, &t3, &t4, a->limb[1], b0, b1, b2, b3);
    uint64_t t6 = p256_wide_mul_row(&t2, &t3, &t4, &t5, a->limb[2], b0, b1, b2, b3);
    uint64_t t7 = p256_wide_mul_row(&t3, &t4, &t5, &t6, a->limb[3], b0, b1, b2, b3);
    // o may alias a or b: every limb of both was read above, and nothing wrote o before this
    // line.
    reduce(o->limb, t0, t1, t2, t3, t4, t5, t6, t7);
}

void p256_wide_fe_sqr(p256_wide_fe *o, const p256_wide_fe *a) {
    p256_wide_fe_mul(o, a, a);
}

void p256_wide_fe_to_mont(p256_wide_fe *o, const p256_wide_fe *a) {
    p256_wide_fe_mul(o, a, &RR);
}

void p256_wide_fe_from_mont(p256_wide_fe *o, const p256_wide_fe *a) {
    p256_wide_fe_mul(o, a, &ONE);
}

// o = a^(2^n): n squarings in a row. n is a constant at every call.
static void sqr_times(p256_wide_fe *o, const p256_wide_fe *a, int n) {
    p256_wide_fe_sqr(o, a);
    for (int i = 1; i < n; i++) {
        p256_wide_fe_sqr(o, o);
    }
}

// o = a^(p-2), with p - 2 = 2^256 - 2^224 + 2^192 + 2^96 - 3. In binary, most significant bit
// first, that is 32 ones, 31 zeros, a one, 96 zeros, 94 ones, a zero and a one. ones_n holds
// a^(2^n - 1), whose exponent is n one bits, and the chain shifts each run of ones into place
// with squarings: 255 of them and 12 multiplies, the same for every a.
void p256_wide_fe_inv(p256_wide_fe *o, const p256_wide_fe *a) {
    p256_wide_fe ones_2;
    p256_wide_fe ones_3;
    p256_wide_fe ones_6;
    p256_wide_fe ones_12;
    p256_wide_fe ones_15;
    p256_wide_fe ones_30;
    p256_wide_fe ones_32;
    p256_wide_fe t;
    p256_wide_fe_sqr(&t, a);
    p256_wide_fe_mul(&ones_2, &t, a);
    p256_wide_fe_sqr(&t, &ones_2);
    p256_wide_fe_mul(&ones_3, &t, a);
    sqr_times(&t, &ones_3, 3);
    p256_wide_fe_mul(&ones_6, &t, &ones_3);
    sqr_times(&t, &ones_6, 6);
    p256_wide_fe_mul(&ones_12, &t, &ones_6);
    sqr_times(&t, &ones_12, 3);
    p256_wide_fe_mul(&ones_15, &t, &ones_3);
    sqr_times(&t, &ones_15, 15);
    p256_wide_fe_mul(&ones_30, &t, &ones_15);
    sqr_times(&t, &ones_30, 2);
    p256_wide_fe_mul(&ones_32, &t, &ones_2);
    sqr_times(&t, &ones_32, 32);
    p256_wide_fe_mul(&t, &t, a); // 32 ones, 31 zeros, a one
    sqr_times(&t, &t, 128);
    p256_wide_fe_mul(&t, &t, &ones_32); // then 96 zeros and 32 ones
    sqr_times(&t, &t, 32);
    p256_wide_fe_mul(&t, &t, &ones_32); // then 32 more ones
    sqr_times(&t, &t, 30);
    p256_wide_fe_mul(&t, &t, &ones_30); // then 30 more ones
    sqr_times(&t, &t, 2);
    p256_wide_fe_mul(o, &t, a); // then a zero and a one
    ct_wipe(&ones_2, sizeof ones_2);
    ct_wipe(&ones_3, sizeof ones_3);
    ct_wipe(&ones_6, sizeof ones_6);
    ct_wipe(&ones_12, sizeof ones_12);
    ct_wipe(&ones_15, sizeof ones_15);
    ct_wipe(&ones_30, sizeof ones_30);
    ct_wipe(&ones_32, sizeof ones_32);
    ct_wipe(&t, sizeof t);
}

#endif // CH_CPU_RUNTIME
