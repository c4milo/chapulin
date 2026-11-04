// RSA's Montgomery multiplication and square in blocks of four words (rsa_mont64_blocks.h).
//
// Every sum here is a 128-bit sum that wraps nothing, as rsa_mont64.c's are. A block adds
// x * (y3 : y2 : y1 : y0) and a word w to four words of the running sum, which is at most
// (2^64 - 1) * (2^256 - 1) + 2^64 - 1 + 2^256 - 1 = 2^320 - 1: five words hold it, so the word
// the block returns cannot wrap. proof/rsa_mont64_blocks_sums_harness.c runs both routines with
// --unsigned-overflow-check on, so each of those sums is a property CBMC checks.
//
// Constant time: no branch and no memory index depends on a word. The branches the file
// compiles to are loops over word counts.
#include "rsa_mont64_blocks.h"

#ifdef CH_CPU_RUNTIME
#if RSA_MONT64_BLOCKS

#include <string.h>

#include "ct.h"

#define WORDS_MAX RSA_MONT64_WORDS_MAX

// (t[3] : t[2] : t[1] : t[0]) and the word returned = the four words + *x * (y[3] : ... : y[0])
// + w. The low halves of the four products go down one carry chain and the high halves, with w
// below them, down another.
//
// x and y are both read through volatile pointers, at the product that uses each word. The
// first block of every round of the multiplication reads the same four words of b and of m, so
// without it clang for arm64 loads them once before the rounds and keeps them, spilled to the
// stack, for the whole call; bin/rsa_sign_equiv_test found three words of b left there.
static inline uint64_t block_mul_add(uint64_t t[4], const volatile uint64_t *x,
                                     const volatile uint64_t *y, uint64_t w) {
    ct_u128 p0 = ct_mul128(*x, y[0]);
    ct_u128 p1 = ct_mul128(*x, y[1]);
    ct_u128 p2 = ct_mul128(*x, y[2]);
    ct_u128 p3 = ct_mul128(*x, y[3]);
    ct_u128 sum = (ct_u128)t[0] + (uint64_t)p0;
    t[0] = (uint64_t)sum;
    sum = (ct_u128)t[1] + (uint64_t)p1 + (uint64_t)(sum >> 64);
    t[1] = (uint64_t)sum;
    sum = (ct_u128)t[2] + (uint64_t)p2 + (uint64_t)(sum >> 64);
    t[2] = (uint64_t)sum;
    sum = (ct_u128)t[3] + (uint64_t)p3 + (uint64_t)(sum >> 64);
    t[3] = (uint64_t)sum;
    uint64_t low_carry = (uint64_t)(sum >> 64);
    sum = (ct_u128)t[0] + w;
    t[0] = (uint64_t)sum;
    sum = (ct_u128)t[1] + (uint64_t)(p0 >> 64) + (uint64_t)(sum >> 64);
    t[1] = (uint64_t)sum;
    sum = (ct_u128)t[2] + (uint64_t)(p1 >> 64) + (uint64_t)(sum >> 64);
    t[2] = (uint64_t)sum;
    sum = (ct_u128)t[3] + (uint64_t)(p2 >> 64) + (uint64_t)(sum >> 64);
    t[3] = (uint64_t)sum;
    return (uint64_t)(p3 >> 64) + low_carry + (uint64_t)(sum >> 64);
}

// t[0..n) and the word returned = t[0..n) + *x * y[0..n) + w: blocks of four, and then one word
// at a time, as rsa_mont64.c's loops step.
static uint64_t row_mul_add(uint64_t *t, const volatile uint64_t *x, const volatile uint64_t *y,
                            size_t n, uint64_t w) {
    size_t j = 0;
    for (; j + 4 <= n; j += 4) {
        w = block_mul_add(t + j, x, y + j, w);
    }
    for (; j < n; j++) {
        ct_u128 sum = ct_mul128(*x, y[j]) + t[j] + w;
        t[j] = (uint64_t)sum;
        w = (uint64_t)(sum >> 64);
    }
    return w;
}

// Round i adds a[i] * b and u * m to the running sum and moves it down one word, as
// rsa_mont64_mont_mul's rounds do, a block of four words at a time. The first block of a round
// adds a[i] * b first, which gives the low word u is made from, and then u * m, which makes that
// word zero. The running sum is k + 1 words and below 2m after every round, and u is kept in the
// word above it, for the reason rsa_mont64_mont_mul keeps its own there.
uint64_t rsa_mont64_blocks_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                               const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    const uint64_t *m = mod->m;
    uint64_t t[WORDS_MAX + 2];
    memset(t, 0, (k + 2) * sizeof(uint64_t));
    volatile uint64_t *u = &t[k + 1];
    const volatile uint64_t *m0inv = &mod->m0inv;
    for (size_t i = 0; i < k; i++) {
        const volatile uint64_t *a_word = &a[i];
        uint64_t s[4] = {t[0], t[1], t[2], t[3]};
        uint64_t ab_carry = block_mul_add(s, a_word, b, 0);
        *u = (uint64_t)ct_mul128(s[0], *m0inv);
        uint64_t um_carry = block_mul_add(s, u, m, 0);
        t[0] = s[1];
        t[1] = s[2];
        t[2] = s[3];
        for (size_t j = 4; j < k; j += 4) {
            s[0] = t[j];
            s[1] = t[j + 1];
            s[2] = t[j + 2];
            s[3] = t[j + 3];
            ab_carry = block_mul_add(s, a_word, b + j, ab_carry);
            um_carry = block_mul_add(s, u, m + j, um_carry);
            t[j - 1] = s[0];
            t[j] = s[1];
            t[j + 1] = s[2];
            t[j + 2] = s[3];
        }
        ct_u128 top = (ct_u128)t[k] + ab_carry + um_carry;
        t[k - 1] = (uint64_t)top;
        t[k] = (uint64_t)(top >> 64);
    }
    uint64_t top = t[k];
    memcpy(o, t, k * sizeof(uint64_t));
    // t held a * b / R and the last round's u above it, as secret as the product.
    ct_wipe(t, (k + 2) * sizeof(uint64_t));
    return top;
}

// The square of a is the cross products a_i a_j, i < j, each once and doubled, and the squares
// a_i^2: a row for each i adds a_i times the words above it at word 2i + 1, the doubling shifts
// the 2k words up a bit, and the squares go in at words 2i. The sum is a^2 < m^2. Row i of the
// reduction then adds u_i * m at word i, which makes word i zero, and the last k words, below
// (m^2 + R m) / R < 2m, are the result. A carry out of word i + k of row i goes into the word
// above, which `top` holds until a later row adds it.
uint64_t rsa_mont64_blocks_square(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    const uint64_t *m = mod->m;
    uint64_t t[2 * WORDS_MAX + 2];
    memset(t, 0, (2 * k + 2) * sizeof(uint64_t));
    for (size_t i = 0; i + 1 < k; i++) {
        t[i + k] = row_mul_add(t + 2 * i + 1, &a[i], a + i + 1, k - 1 - i, 0);
    }
    uint64_t carry = 0;
    uint64_t moved = 0;
    for (size_t i = 0; i < k; i++) {
        const volatile uint64_t *a_word = &a[i];
        ct_u128 square = ct_mul128(*a_word, *a_word);
        uint64_t low = (t[2 * i] << 1) | moved;
        uint64_t high = (t[2 * i + 1] << 1) | (t[2 * i] >> 63);
        moved = t[2 * i + 1] >> 63;
        ct_u128 sum = (ct_u128)low + (uint64_t)square + carry;
        t[2 * i] = (uint64_t)sum;
        sum = (ct_u128)high + (uint64_t)(square >> 64) + (uint64_t)(sum >> 64);
        t[2 * i + 1] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
    }
    volatile uint64_t *u = &t[2 * k + 1];
    const volatile uint64_t *m0inv = &mod->m0inv;
    uint64_t top = 0;
    for (size_t i = 0; i < k; i++) {
        *u = (uint64_t)ct_mul128(t[i], *m0inv);
        uint64_t w = row_mul_add(t + i, u, m, k, 0);
        ct_u128 sum = (ct_u128)t[i + k] + w + top;
        t[i + k] = (uint64_t)sum;
        top = (uint64_t)(sum >> 64);
    }
    memcpy(o, t + k, k * sizeof(uint64_t));
    // t held a^2 and the reduction's u above it, as secret as a.
    ct_wipe(t, (2 * k + 2) * sizeof(uint64_t));
    return top;
}

#endif // RSA_MONT64_BLOCKS
#endif // CH_CPU_RUNTIME
