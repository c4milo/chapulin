// Poly1305's block step of RFC 8439 §2.5 on three 64-bit limbs in general
// registers, for an x86-64 host object's one-pass ChaCha20-Poly1305
// (aead_avx2.c, docs/decisions.md 206). The accumulator h is h0 + h1 2^64
// + h2 2^128, and r is r0 + r1 2^64. A block's products are four 64x64->128
// widening multiplies on ct_mul128 and two 64-bit products by h2, so the
// step runs on the scalar multiplier while the AVX2 ChaCha20 rounds run on
// the vector units. The caller's CH_CPU_CONSTANT_TIME_MULTIPLY states the
// timing of ct_mul128's multiply, as it does for x25519_wide.c's.
//
// Every step is adds with carries, shifts by constants, masks and
// multiplies, with no branch and no address computed from h, r or the
// message. poly1305.c's loop stays the reference: bin/aead_avx2_equiv_test
// compares the one pass with the two-pass AEAD, and the poly1305_wide
// harnesses and spec/lean/Spec/Poly1305Wide.lean hold the step itself.
//
// The sum of three words has two forms, and POLY1305_WIDE_ADC names the one
// a build compiles:
//
//   1  gcc for x86-64: one statement of ADD, ADC and ADC. gcc 13 writes no
//      ADC for a carry that C computes from a comparison, and its form of
//      the C took 15 more instructions a block (docs/decisions.md 211).
//   0  every other build: the comparisons, which clang writes as ADD, ADC
//      and ADC. The harnesses in proof/ name this form, which CBMC reads.
//
// bin/aead_avx2_equiv_test holds the form its build compiles to a sum in
// 128-bit arithmetic, and bin/diff_poly1305_wide holds the step over it to
// the Lean model.
//
// The bounds the step keeps, which the harnesses prove for every input
// within them and the Lean module states:
//   - r0 and r1 below 2^60, r1 a multiple of 4: the clamp of RFC 8439
//     §2.5.1 leaves both so.
//   - h2 at most 4 on entry, and on return.
#ifndef CH_POLY1305_WIDE_H
#define CH_POLY1305_WIDE_H

#include <stddef.h>
#include <stdint.h>

#include "ct.h"

#ifdef CH_CPU_RUNTIME

#ifndef POLY1305_WIDE_ADC
#if defined(__GNUC__) && !defined(__clang__) && defined(__x86_64__)
#define POLY1305_WIDE_ADC 1
#else
#define POLY1305_WIDE_ADC 0
#endif
#endif

// r and 5/4 of r1, which a product past 2^130 takes: modulo 2^130 - 5,
// 2^128 r1 h1 2^0 is 2^130 (r1 / 4) h1, which is 5 (r1 / 4) h1.
typedef struct {
    uint64_t r0;
    uint64_t r1;
    uint64_t s1;
} poly1305_wide_key;

// The accumulator: h0 + h1 2^64 + h2 2^128, with h2 at most 4.
typedef struct {
    uint64_t h0;
    uint64_t h1;
    uint64_t h2;
} poly1305_wide_acc;

// The 26-bit word mask of poly1305.c's words.
#define POLY1305_WIDE_WORD 0x3ffffffU

static inline uint64_t poly1305_wide_load64(const uint8_t *p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

// The key from poly1305.c's five words of r, each below 2^26, which hold
// r below 2^124.
static inline void poly1305_wide_key_of(poly1305_wide_key *k, const uint32_t r[5]) {
    ct_u128 value = (ct_u128)r[0] | ((ct_u128)r[1] << 26) | ((ct_u128)r[2] << 52) |
                    ((ct_u128)r[3] << 78) | ((ct_u128)r[4] << 104);
    k->r0 = (uint64_t)value;
    k->r1 = (uint64_t)(value >> 64);
    k->s1 = k->r1 + (k->r1 >> 2);
}

// The accumulator from poly1305.c's five words, as its loop leaves them:
// h0, h2, h3 and h4 below 2^26 and h1 at most 2^26, so h2 is at most 4.
// The words reach past 2^128, so the sum runs in two halves of 64 bits.
static inline void poly1305_wide_from_words(poly1305_wide_acc *a, const uint32_t h[5]) {
    ct_u128 low = (ct_u128)h[0] + ((ct_u128)h[1] << 26) + ((ct_u128)h[2] << 52);
    a->h0 = (uint64_t)low;
    ct_u128 high = (low >> 64) + ((ct_u128)h[3] << 14) + ((ct_u128)h[4] << 40);
    a->h1 = (uint64_t)high;
    a->h2 = (uint64_t)(high >> 64);
}

// The sum of x and y modulo 2^64, and in *carry 1 where it passed 2^64.
// The sum runs in 128 bits and keeps its low word, so no 64-bit sum wraps
// and --unsigned-overflow-check sees every other sum. The carry compares
// the low word with an operand, which compilers write as the carry flag:
// add and setb or adc, no branch. A carry read from the high word of the
// 128-bit sum made gcc 13 keep the limbs that sum fed as 128-bit values and
// multiply them in three products where one was enough (docs/decisions.md
// 206).
static inline __attribute__((always_inline)) uint64_t poly1305_wide_add(uint64_t x, uint64_t y,
                                                                        uint64_t *carry) {
    uint64_t sum = (uint64_t)((ct_u128)x + y);
    *carry = (uint64_t)(sum < y);
    return sum;
}

// (h2 : h1 : h0) = (h2 : h1 : h0) + (m2 : m1 : m0), three words with the
// carry out of each of the lower two added to the word above. The caller
// keeps h2 + m2 + 2 below 2^64, so the top word does not wrap. Neither form
// has a branch. The statement of the first form reads m0 to m2 as
// registers, immediates or memory at an address the caller computed from
// nothing secret, and names the flags it writes.
static inline __attribute__((always_inline)) void
poly1305_wide_sum(uint64_t *h0, uint64_t *h1, uint64_t *h2, uint64_t m0, uint64_t m1, uint64_t m2) {
#if POLY1305_WIDE_ADC
    __asm__("add %[m0], %[h0]\n adc %[m1], %[h1]\n adc %[m2], %[h2]"
            : [h0] "+&r"(*h0), [h1] "+&r"(*h1), [h2] "+r"(*h2)
            : [m0] "rme"(m0), [m1] "rme"(m1), [m2] "rme"(m2)
            : "cc");
#else
    uint64_t carry = 0;
    uint64_t carry_high = 0;
    *h0 = poly1305_wide_add(*h0, m0, &carry);
    uint64_t sum = poly1305_wide_add(*h1, m1, &carry_high);
    *h1 = poly1305_wide_add(sum, carry, &carry);
    *h2 = *h2 + m2 + carry_high + carry;
#endif
}

// h2 at or above 4 folded down: the bits at 2^130 and up, times 5, added
// at 2^0.
static inline __attribute__((always_inline)) void poly1305_wide_fold(poly1305_wide_acc *a) {
    uint64_t c = (a->h2 >> 2) * 5;
    uint64_t h0 = a->h0;
    uint64_t h1 = a->h1;
    uint64_t h2 = a->h2 & 3;
    poly1305_wide_sum(&h0, &h1, &h2, c, 0, 0);
    a->h0 = h0;
    a->h1 = h1;
    a->h2 = h2;
}

// poly1305.c's five words from the accumulator, each below 2^26. Two folds
// leave h2 at most 3: after the first h2 is 4 only where h1 and h0 were
// carried past 2^64, so they are below 5, and the second adds 5 to h0.
static inline void poly1305_wide_to_words(uint32_t h[5], poly1305_wide_acc *a) {
    poly1305_wide_fold(a);
    poly1305_wide_fold(a);
    h[0] = (uint32_t)a->h0 & POLY1305_WIDE_WORD;
    h[1] = (uint32_t)(a->h0 >> 26) & POLY1305_WIDE_WORD;
    h[2] = (uint32_t)((a->h0 >> 52) | (a->h1 << 12)) & POLY1305_WIDE_WORD;
    h[3] = (uint32_t)(a->h1 >> 14) & POLY1305_WIDE_WORD;
    h[4] = (uint32_t)((a->h1 >> 40) | (a->h2 << 24));
}

// One block at m with its 2^128 bit: h = (h + m + 2^128) r, partly reduced
// modulo 2^130 - 5. gcc 13 called an out-of-line copy from the round loop
// of aead_avx2.c's pass_hashing, so the attribute makes it inline.
static inline __attribute__((always_inline)) void
poly1305_wide_block(poly1305_wide_acc *a, const poly1305_wide_key *k, const uint8_t m[16]) {
    uint64_t h0 = a->h0;
    uint64_t h1 = a->h1;
    uint64_t h2 = a->h2;
    poly1305_wide_sum(&h0, &h1, &h2, poly1305_wide_load64(m), poly1305_wide_load64(m + 8), 1);
    ct_u128 d0 = ct_mul128(h0, k->r0) + ct_mul128(h1, k->s1);
    ct_u128 d1 = ct_mul128(h0, k->r1) + ct_mul128(h1, k->r0) + (ct_u128)(h2 * k->s1);
    uint64_t d2 = h2 * k->r0;
    d1 += (uint64_t)(d0 >> 64);
    d2 += (uint64_t)(d1 >> 64);
    a->h0 = (uint64_t)d0;
    a->h1 = (uint64_t)d1;
    a->h2 = d2;
    poly1305_wide_fold(a);
}

#endif // CH_CPU_RUNTIME

#endif
