// The long division of rsa_mont.c's host arm, which that file alone
// includes: a remainder times 2^64 modulo a modulus whose top bit is set,
// a step at a time (docs/decisions.md 103 and 208). rsa_vp1 runs k steps
// to multiply a signature by R = 2^(64k) modulo n, and on x86-64
// rsa_vp1_cpu runs them for the power of two a kernel takes.
//
// Every operand here is public: a modulus, a signature, and remainders
// computed from them. So the steps branch on their words and call the
// compiler's 128-bit division, and the file carries none of the
// constant-time terms of rsa_mont64.h. No function here may take a
// signer's words.
//
// spec/lean/Spec/RsaDivision.lean models the estimate and both forms of
// the step from this file and proves their value, and
// bin/diff_rsa_division holds the C to the model.
#ifndef CH_RSA_MONT_DIVISION_H
#define CH_RSA_MONT_DIVISION_H

#include <stddef.h>
#include <stdint.h>

#include "ct.h"
#include "rsa_mont64.h"
#include "rsa_mont64_blocks.h"

#ifdef CH_CPU_RUNTIME

// The estimate of floor(rem * 2^64 / m) that a step of the long division
// below takes, for rem below m and an m of k >= 2 words whose top bit is
// set. It divides the top two words of rem by m's top word. The quotient
// is below 2^64, because rem is below m. When rem's top word equals m's,
// that division passes 2^64, and the estimate is 2^64 - 1. Knuth's
// Theorem B (The Art of Computer Programming, vol. 2, 4.3.1) says the
// estimate is the quotient or at most 2 above it, because m's top word is
// at least 2^63. spec/lean/Spec/RsaDivision.lean proves both bounds, as
// `quotient_le_estimate` and `estimate_le_quotient_add_two`.
static uint64_t quotient_estimate(const uint64_t *rem, const uint64_t *m, size_t k) {
    uint64_t top = rem[k - 1];
    uint64_t estimate = UINT64_MAX;
    if (top < m[k - 1]) {
        estimate = (uint64_t)((((ct_u128)top << 64) | rem[k - 2]) / m[k - 1]);
    }
    return estimate;
}

// rem = rem * 2^64 mod m, for rem below m and an m of k >= 2 words whose
// top bit is set. It is one step of a long division, Knuth's algorithm D,
// whose dividend is rem with a zero word below it. The step subtracts the
// estimate times m and then adds m back, at most twice.
//
// m and rem are public for every caller, so every value here is public:
// the step branches on them, and the division takes whatever time it
// takes.
static void times_word_mod(uint64_t *rem, const uint64_t *m, size_t k) {
    uint64_t estimate = quotient_estimate(rem, m, k);
    // The dividend less the estimate times m, from the bottom word up.
    // Word j of the dividend is rem[j - 1], and word 0 is zero. A
    // subtraction adds the complement and one, as rsa_mont64.c's do, so
    // the carry out is 1 where no borrow happened.
    uint64_t dividend_word = 0;
    uint64_t product_carry = 0;
    uint64_t carry = 1;
    for (size_t j = 0; j < k; j++) {
        ct_u128 product = ct_mul128(estimate, m[j]) + product_carry;
        product_carry = (uint64_t)(product >> 64);
        ct_u128 difference = (ct_u128)dividend_word + ~(uint64_t)product + carry;
        dividend_word = rem[j];
        rem[j] = (uint64_t)difference;
        carry = (uint64_t)(difference >> 64);
    }
    // The difference's word above the k, in two's complement: 0 when the
    // difference is at or above zero, and 2^64 - 1 or 2^64 - 2 when the
    // estimate was 1 or 2 too large. Each pass adds m, and the carry out
    // of its top word moves that word toward 0, where it wraps on purpose.
    uint64_t above = (uint64_t)((ct_u128)dividend_word + ~product_carry + carry);
    for (int pass = 0; pass < 2 && above != 0; pass++) {
        uint64_t sum_carry = 0;
        for (size_t j = 0; j < k; j++) {
            ct_u128 sum = (ct_u128)rem[j] + m[j] + sum_carry;
            rem[j] = (uint64_t)sum;
            sum_carry = (uint64_t)(sum >> 64);
        }
        above += sum_carry;
    }
}

#if RSA_MONT64_BLOCKS
// rem = rem + m over k words, for a k that is a multiple of 4, and the
// carry out of the top word. A block adds four words of m down one carry
// chain and the carry from the block below down another, which clang
// compiles to add-with-carry instructions, as it compiles the two chains
// of rsa_mont64_block_add.
static uint64_t add_modulus_blocks(uint64_t *rem, const uint64_t *m, size_t k) {
    uint64_t carry = 0;
    for (size_t j = 0; j < k; j += 4) {
        ct_u128 sum = (ct_u128)rem[j] + m[j];
        uint64_t s0 = (uint64_t)sum;
        sum = (ct_u128)rem[j + 1] + m[j + 1] + (uint64_t)(sum >> 64);
        uint64_t s1 = (uint64_t)sum;
        sum = (ct_u128)rem[j + 2] + m[j + 2] + (uint64_t)(sum >> 64);
        uint64_t s2 = (uint64_t)sum;
        sum = (ct_u128)rem[j + 3] + m[j + 3] + (uint64_t)(sum >> 64);
        uint64_t s3 = (uint64_t)sum;
        uint64_t high = (uint64_t)(sum >> 64);
        sum = (ct_u128)s0 + carry;
        rem[j] = (uint64_t)sum;
        sum = (ct_u128)s1 + (uint64_t)(sum >> 64);
        rem[j + 1] = (uint64_t)sum;
        sum = (ct_u128)s2 + (uint64_t)(sum >> 64);
        rem[j + 2] = (uint64_t)sum;
        sum = (ct_u128)s3 + (uint64_t)(sum >> 64);
        rem[j + 3] = (uint64_t)sum;
        // Eight words and the carry in are at most 2^257 - 1 together, so
        // at most one of the two chains carries out.
        carry = high + (uint64_t)(sum >> 64);
    }
    return carry;
}

// times_word_mod in blocks of four words, for a k that is a multiple of
// 4: the same estimate, and the same words in rem. negated holds R - m
// over k words, with R = 2^(64k).
//
// rem * 2^64 - estimate * m is rem * 2^64 + estimate * (R - m), less
// estimate * R. So the step adds the estimate times negated to rem moved
// up one word, four products a block, as rsa_mont64_blocks.c's rows add
// theirs. Then it takes the estimate off the word above the k. That sum's
// word above the k can carry out of 64 bits, and the subtraction of the
// estimate takes the carry back, so the word is times_word_mod's modulo
// 2^64. spec/lean/Spec/RsaDivision.lean proves the two steps equal, as
// `timesWordBlocks_eq`.
static void times_word_mod_blocks(uint64_t *rem, const uint64_t *m, const uint64_t *negated,
                                  size_t k) {
    uint64_t estimate = quotient_estimate(rem, m, k);
    // Word j of rem moved up one word is rem[j - 1], and word 0 is zero.
    // moved holds the word that the block below hands up. s is one array
    // for the whole step, as rsa_mont64_blocks.c's rounds keep theirs: an
    // array declared in the loop is an object of cbmc's formula at each
    // block, and a division of 576 blocks passed the 256 it numbers.
    uint64_t s[4] = {0};
    uint64_t moved = 0;
    uint64_t carry = 0;
    for (size_t j = 0; j < k; j += 4) {
        s[0] = moved;
        s[1] = rem[j];
        s[2] = rem[j + 1];
        s[3] = rem[j + 2];
        moved = rem[j + 3];
        carry = rsa_mont64_block_add(s, estimate, negated[j], negated[j + 1], negated[j + 2],
                                     negated[j + 3], carry);
        rem[j] = s[0];
        rem[j + 1] = s[1];
        rem[j + 2] = s[2];
        rem[j + 3] = s[3];
    }
    // The word above the k less the estimate, modulo 2^64: 0, 2^64 - 1 or
    // 2^64 - 2, as in times_word_mod. The sum wraps on purpose.
    uint64_t above = moved + carry - estimate;
    for (int pass = 0; pass < 2 && above != 0; pass++) {
        above += add_modulus_blocks(rem, m, k);
    }
}
#endif

// x = x R mod m, with R = 2^(64k), for x below m and an m of k >= 2 words
// whose top bit is set: k steps of the long division, each of which
// multiplies x by 2^64 modulo m. Where rsa_mont64.h's RSA_MONT64_BLOCKS
// is 1 and k is a multiple of 4, the steps run in blocks of four words.
static void times_r_mod(uint64_t *x, const uint64_t *m, size_t k) {
#if RSA_MONT64_BLOCKS
    if (k % 4 == 0) {
        // R - m over k words: the complement of m, plus one.
        uint64_t negated[RSA_MONT64_WORDS_MAX];
        uint64_t carry = 1;
        for (size_t j = 0; j < k; j++) {
            ct_u128 sum = (ct_u128)~m[j] + carry;
            negated[j] = (uint64_t)sum;
            carry = (uint64_t)(sum >> 64);
        }
        for (size_t i = 0; i < k; i++) {
            times_word_mod_blocks(x, m, negated, k);
        }
        return;
    }
#endif
    for (size_t i = 0; i < k; i++) {
        times_word_mod(x, m, k);
    }
}

#endif // CH_CPU_RUNTIME

#endif
