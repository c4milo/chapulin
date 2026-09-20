// Constant-time arithmetic modulo the P-256 field prime (see
// p256_field.h for the contracts and for why p256.c's arithmetic cannot
// be reused). Elements are eight little-endian uint32 limbs; products
// and carries live in uint64. Multiplication reduces word by word
// (CIOS, Koç et al.), inverses are Fermat powers, and every conditional
// subtraction is a mask and a select rather than an `if`.
#include "p256_field.h"

#include <stddef.h>

#include "ct.h"

#define LIMBS P256_FE_LIMBS

// SEC 2 secp256r1's field prime and the constants derived from it,
// R = 2^256. The same prime limbs appear in p256.c's MODP.
// test/gen_p256_field_vectors.py recomputes p, 2^512 mod p, R mod p and
// p-2 from p's definition and stops if any limb below differs.
static const uint32_t P[LIMBS] = {0xffffffff, 0xffffffff, 0xffffffff, 0x00000000,
                                  0x00000000, 0x00000000, 0x00000001, 0xffffffff};
// 2^512 mod p: multiplying by it enters the Montgomery domain.
static const uint32_t RR[LIMBS] = {0x00000003, 0x00000000, 0xffffffff, 0xfffffffb,
                                   0xfffffffe, 0xffffffff, 0xfffffffd, 0x00000004};
// -p^-1 mod 2^32. It is 1 for this prime, because p's low limb is
// 2^32 - 1, so the CIOS multiplier below costs nothing on any target.
#define P0_INV 1U

const p256_fe p256_fe_zero = {
    {0, 0, 0, 0, 0, 0, 0, 0}
};
// 2^256 mod p, which is 2^256 - p.
const p256_fe p256_fe_one_mont = {
    {0x00000001, 0x00000000, 0x00000000, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
     0x00000000}
};

static const uint32_t ONE[LIMBS] = {1, 0, 0, 0, 0, 0, 0, 0};

// p - 2, the Fermat exponent, most significant limb last. It is a
// constant of this build, so p256_fe_inv's walk over its bits is the
// same walk on every call.
static const uint32_t P_MINUS_2[LIMBS] = {0xfffffffd, 0xffffffff, 0xffffffff, 0x00000000,
                                          0x00000000, 0x00000000, 0x00000001, 0xffffffff};

// o = a + b over the limbs; the return value is the carry out, 0 or 1.
static uint32_t add_limbs(uint32_t o[LIMBS], const uint32_t a[LIMBS], const uint32_t b[LIMBS]) {
    uint64_t carry = 0;
    for (int i = 0; i < LIMBS; i++) {
        carry += (uint64_t)a[i] + b[i];
        o[i] = (uint32_t)carry;
        carry >>= 32;
    }
    return (uint32_t)carry;
}

// o = a - b over the limbs; the return value is the borrow out as a
// mask, all ones when a < b and zero otherwise. The mask comes straight
// out of the last difference's high word: a negative uint64 difference
// of two limbs and a borrow bit has all ones there, and a non-negative
// one has zeros, so no caller has to negate a bit to get a mask.
static uint32_t sub_limbs(uint32_t o[LIMBS], const uint32_t a[LIMBS], const uint32_t b[LIMBS]) {
    uint64_t borrow = 0;
    uint64_t diff = 0;
    for (int i = 0; i < LIMBS; i++) {
        diff = (uint64_t)a[i] - b[i] - borrow;
        o[i] = (uint32_t)diff;
        borrow = (diff >> 32) & 1;
    }
    return (uint32_t)(diff >> 32);
}

// o = a when mask is all ones, o = b when mask is zero.
static void select_limbs(uint32_t o[LIMBS], const uint32_t a[LIMBS], const uint32_t b[LIMBS],
                         uint32_t mask) {
    for (int i = 0; i < LIMBS; i++) {
        o[i] = (a[i] & mask) | (b[i] & ~mask);
    }
}

// o = (high:t) - p when that 257-bit value is at or above p, o = t
// otherwise. high is 0 or 1: a sum of two elements below p carries at
// most one bit past the eight limbs, and the CIOS loop below leaves at
// most one there too (proof/p256_field_harness.c).
static void reduce_once(uint32_t o[LIMBS], const uint32_t t[LIMBS], uint32_t high) {
    uint32_t reduced[LIMBS];
    uint32_t borrow = sub_limbs(reduced, t, P) & 1U;
    // high and borrow are each 0 or 1, and high:t is below p exactly
    // when high is 0 and the low subtraction borrowed out. Their
    // difference in uint64 arithmetic is negative in that one case, so
    // its high word is all ones there and zero elsewhere; the
    // complement is the mask that takes the reduced limbs. Nothing here
    // negates a 0-or-1 value, which is the shape gcc rewrites into a
    // multiply by that value (ct.h,
    // https://github.com/c4milo/chapulin/issues/106).
    uint64_t below = (uint64_t)high - borrow;
    select_limbs(o, reduced, t, ~(uint32_t)(below >> 32));
}

// All ones when v is zero, zero otherwise.
static uint32_t zero_mask_word(uint32_t v) {
    uint32_t nonzero = v | (~v + 1U); // bit 31 is set exactly when v is nonzero
    return (nonzero >> 31) - 1U;
}

// o = a*b/R mod p (CIOS, Koç et al.). Each round adds one limb of a into
// t, then adds a multiple of p that zeroes t's low limb and shifts t
// down by one limb. Every product goes through ct_widemul, so no
// widening multiply instruction reads a limb. The carry chain cannot
// overflow and t's ninth word holds at most one bit; both are
// proof/p256_mul_harness.c's lemma.
static void mont_mul(uint32_t o[LIMBS], const uint32_t a[LIMBS], const uint32_t b[LIMBS]) {
    uint32_t t[LIMBS + 2] = {0};
    for (int i = 0; i < LIMBS; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < LIMBS; j++) {
            uint64_t v = ct_widemul(a[i], b[j]) + t[j] + carry;
            t[j] = (uint32_t)v;
            carry = v >> 32;
        }
        uint64_t v = (uint64_t)t[LIMBS] + carry;
        t[LIMBS] = (uint32_t)v;
        t[LIMBS + 1] = (uint32_t)(v >> 32);

        uint32_t u = t[0] * P0_INV;
        carry = (ct_widemul(u, P[0]) + t[0]) >> 32;
        for (int j = 1; j < LIMBS; j++) {
            v = ct_widemul(u, P[j]) + t[j] + carry;
            t[j - 1] = (uint32_t)v;
            carry = v >> 32;
        }
        v = (uint64_t)t[LIMBS] + carry;
        t[LIMBS - 1] = (uint32_t)v;
        t[LIMBS] = t[LIMBS + 1] + (uint32_t)(v >> 32);
        t[LIMBS + 1] = 0;
    }
    // t is below 2p with at most one bit in t[LIMBS], so one conditional
    // subtraction finishes it. o may alias a or b: nothing writes o
    // before this line.
    reduce_once(o, t, t[LIMBS]);
}

void p256_fe_from_bytes(p256_fe *o, const uint8_t in[P256_FE_LEN]) {
    for (size_t i = 0; i < LIMBS; i++) {
        const uint8_t *word = in + P256_FE_LEN - 4 * (i + 1);
        o->limb[i] = ((uint32_t)word[0] << 24) | ((uint32_t)word[1] << 16) |
                     ((uint32_t)word[2] << 8) | (uint32_t)word[3];
    }
}

void p256_fe_to_bytes(uint8_t out[P256_FE_LEN], const p256_fe *a) {
    for (size_t i = 0; i < LIMBS; i++) {
        uint8_t *word = out + P256_FE_LEN - 4 * (i + 1);
        word[0] = (uint8_t)(a->limb[i] >> 24);
        word[1] = (uint8_t)(a->limb[i] >> 16);
        word[2] = (uint8_t)(a->limb[i] >> 8);
        word[3] = (uint8_t)a->limb[i];
    }
}

uint32_t p256_fe_reduced_mask(const p256_fe *a) {
    uint32_t discard[LIMBS];
    return sub_limbs(discard, a->limb, P);
}

uint32_t p256_fe_zero_mask(const p256_fe *a) {
    uint32_t bits = 0;
    for (int i = 0; i < LIMBS; i++) {
        bits |= a->limb[i];
    }
    return zero_mask_word(bits);
}

uint32_t p256_fe_equal_mask(const p256_fe *a, const p256_fe *b) {
    uint32_t bits = 0;
    for (int i = 0; i < LIMBS; i++) {
        bits |= a->limb[i] ^ b->limb[i];
    }
    return zero_mask_word(bits);
}

void p256_fe_cmov(p256_fe *o, const p256_fe *a, uint32_t mask) {
    select_limbs(o->limb, a->limb, o->limb, mask);
}

void p256_fe_cswap(p256_fe *a, p256_fe *b, uint32_t mask) {
    for (int i = 0; i < LIMBS; i++) {
        uint32_t exchange = (a->limb[i] ^ b->limb[i]) & mask;
        a->limb[i] ^= exchange;
        b->limb[i] ^= exchange;
    }
}

void p256_fe_add(p256_fe *o, const p256_fe *a, const p256_fe *b) {
    uint32_t sum[LIMBS];
    uint32_t carry = add_limbs(sum, a->limb, b->limb);
    reduce_once(o->limb, sum, carry);
}

void p256_fe_sub(p256_fe *o, const p256_fe *a, const p256_fe *b) {
    uint32_t diff[LIMBS];
    uint32_t wrapped[LIMBS];
    uint32_t borrowed = sub_limbs(diff, a->limb, b->limb);
    // a < b wrapped the difference by 2^256; adding p once lands it back
    // in [0, p), because both inputs are below p.
    (void)add_limbs(wrapped, diff, P);
    select_limbs(o->limb, wrapped, diff, borrowed);
}

void p256_fe_neg(p256_fe *o, const p256_fe *a) {
    uint32_t diff[LIMBS];
    uint32_t is_zero = p256_fe_zero_mask(a);
    // p - a is the negative of every element except zero, where it is p
    // itself and no element at all, so the zero mask takes zero there.
    (void)sub_limbs(diff, P, a->limb);
    select_limbs(o->limb, p256_fe_zero.limb, diff, is_zero);
}

void p256_fe_mul(p256_fe *o, const p256_fe *a, const p256_fe *b) {
    mont_mul(o->limb, a->limb, b->limb);
}

void p256_fe_sqr(p256_fe *o, const p256_fe *a) {
    mont_mul(o->limb, a->limb, a->limb);
}

void p256_fe_to_mont(p256_fe *o, const p256_fe *a) {
    mont_mul(o->limb, a->limb, RR);
}

void p256_fe_from_mont(p256_fe *o, const p256_fe *a) {
    mont_mul(o->limb, a->limb, ONE);
}

void p256_fe_inv(p256_fe *o, const p256_fe *a) {
    p256_fe acc = p256_fe_one_mont;
    // Square and multiply over the bits of p-2, most significant first.
    // The bit decides whether the round multiplies, and it is a bit of a
    // build constant, so the sequence of operations is the same on every
    // call and depends on nothing in a. The index reads the constant,
    // never a. Shifts stand in for / and % (INV-23).
    for (int i = 256 - 1; i >= 0; i--) {
        mont_mul(acc.limb, acc.limb, acc.limb);
        if ((P_MINUS_2[i >> 5] >> (i & 31)) & 1U) {
            mont_mul(acc.limb, acc.limb, a->limb);
        }
    }
    *o = acc;
}
