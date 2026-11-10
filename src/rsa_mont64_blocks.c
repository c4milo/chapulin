// RSA's Montgomery multiplication and square in blocks of four words (rsa_mont64_blocks.h).
//
// Every sum here is a 128-bit sum that wraps nothing, as rsa_mont64.c's are. A block adds
// x * (y3 : y2 : y1 : y0) and a word w to four words of the running sum, which is at most
// (2^64 - 1) * (2^256 - 1) + 2^64 - 1 + 2^256 - 1 = 2^320 - 1: five words hold it, so the word
// the block returns cannot wrap. proof/rsa_mont64_blocks_sums_harness.c runs both routines with
// --unsigned-overflow-check on, so each of those sums is a property CBMC checks.
//
// Constant time: no branch and no memory index depends on a word. The branches the file
// compiles to are loops over word counts, the square's test of a row's index, and the last
// subtraction's tests of where its two arrays lie, before its second pass.
#include "rsa_mont64_blocks.h"

#ifdef CH_CPU_RUNTIME
#if RSA_MONT64_BLOCKS

#include <string.h>

#include "ct.h"

#define WORDS_MAX RSA_MONT64_WORDS_MAX

// rsa_mont64_block_add of *x and four secret words at y. x and y are both read through volatile
// pointers,
// once each for the block, so that no copy outlives the block. The first block of every round of
// the multiplication reads the same four words of b, so without it clang for arm64 loads them once
// before the rounds and keeps them, spilled to the stack, for the whole call;
// bin/rsa_sign_equiv_test found three words of b left there.
static inline uint64_t block_mul_add(uint64_t t[4], const volatile uint64_t *x,
                                     const volatile uint64_t *y, uint64_t w) {
    return rsa_mont64_block_add(t, *x, y[0], y[1], y[2], y[3], w);
}

// rsa_mont64_block_add of *x and four words of the modulus at m_block. The modulus is public, so
// a copy of
// its words in a register or a stack slot holds nothing secret, and the words are read through a
// plain pointer, which lets clang load two words in one instruction.
static inline uint64_t block_mul_add_modulus(uint64_t t[4], const volatile uint64_t *x,
                                             const uint64_t *m_block, uint64_t w) {
    return rsa_mont64_block_add(t, *x, m_block[0], m_block[1], m_block[2], m_block[3], w);
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
        uint64_t um_carry = block_mul_add_modulus(s, u, m, 0);
        t[0] = s[1];
        t[1] = s[2];
        t[2] = s[3];
        for (size_t j = 4; j < k; j += 4) {
            s[0] = t[j];
            s[1] = t[j + 1];
            s[2] = t[j + 2];
            s[3] = t[j + 3];
            ab_carry = block_mul_add(s, a_word, b + j, ab_carry);
            um_carry = block_mul_add_modulus(s, u, m + j, um_carry);
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

// All ones when bit is 1, and all zeros when bit is 0, by the arithmetic shift that
// rsa_mont64.c's mask_of_bit takes.
static uint64_t blocks_mask_of_bit(uint64_t bit) {
    return (uint64_t)((int64_t)(bit << 63) >> 63);
}

// Adds u times the four words at m_block, and w, to t[j..j + 4), writes the four words of the
// sum to t[j - 1..j + 3), one word down, as rsa_mont64_blocks_mul's rounds move theirs, and
// returns the word above them.
static uint64_t reduce_block(uint64_t *t, size_t j, const volatile uint64_t *u,
                             const uint64_t *m_block, uint64_t w) {
    uint64_t s[4] = {t[j], t[j + 1], t[j + 2], t[j + 3]};
    w = block_mul_add_modulus(s, u, m_block, w);
    t[j - 1] = s[0];
    t[j] = s[1];
    t[j + 1] = s[2];
    t[j + 2] = s[3];
    return w;
}

// The same, for a block that first adds a_i times the four words of V_i at v_block.
static uint64_t square_block(uint64_t *t, size_t j, const volatile uint64_t *a_word,
                             const uint64_t *v_block, uint64_t *ab_carry,
                             const volatile uint64_t *u, const uint64_t *m_block, uint64_t w) {
    uint64_t s[4] = {t[j], t[j + 1], t[j + 2], t[j + 3]};
    *ab_carry = block_mul_add(s, a_word, v_block, *ab_carry);
    w = block_mul_add_modulus(s, u, m_block, w);
    t[j - 1] = s[0];
    t[j] = s[1];
    t[j + 1] = s[2];
    t[j + 2] = s[3];
    return w;
}

// Row i of the square: t = (t + a_i V_i + u m) / B, with B = 2^64 and u the multiple of m that
// makes the low word of the sum zero. v holds V_i's k words, which are zero below word i, and
// v[k] is word k of V_i, 0 or 1. The row adds a_i V_i from the block that holds word i, the
// block at first, and below that block it adds u m alone. The running sum stays below 3m, so its
// top word, t[k], is 0, 1 or 2.
static void square_row(uint64_t *t, size_t i, const volatile uint64_t *a_word, const uint64_t *v,
                       volatile uint64_t *u, const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    const uint64_t *m = mod->m;
    const volatile uint64_t *m0inv = &mod->m0inv;
    size_t first = i & ~(size_t)3;
    uint64_t s[4] = {t[0], t[1], t[2], t[3]};
    uint64_t ab_carry = 0;
    if (first == 0) {
        ab_carry = block_mul_add(s, a_word, v, 0);
    }
    *u = (uint64_t)ct_mul128(s[0], *m0inv);
    uint64_t um_carry = block_mul_add_modulus(s, u, m, 0);
    t[0] = s[1];
    t[1] = s[2];
    t[2] = s[3];
    size_t j = 4;
    for (; j < first; j += 4) {
        um_carry = reduce_block(t, j, u, m + j, um_carry);
    }
    for (; j < k; j += 4) {
        um_carry = square_block(t, j, a_word, v + j, &ab_carry, u, m + j, um_carry);
    }
    // Word k: a_i times v[k], which is 0 or 1, so a_i under a mask.
    const volatile uint64_t *v_top = &v[k];
    uint64_t top_word = *a_word & blocks_mask_of_bit(*v_top);
    ct_u128 top = (ct_u128)t[k] + ab_carry + um_carry + top_word;
    t[k - 1] = (uint64_t)top;
    t[k] = (uint64_t)(top >> 64);
}

// The square of a is the sum over i of a_i B^i V_i, where
// V_i = a_i B^i + 2 (a_{i+1} B^{i+1} + ... + a_{k-1} B^{k-1}). Row i holds each cross product
// a_i a_j with i < j once and doubled, and the square a_i^2 once. The words of V_i are:
//
//   - zero below word i, and a_i at word i;
//   - a_{i+1} moved up one bit at word i + 1;
//   - above them, the words of 2a: word j is a_j moved up one bit, with the top bit of a_{j-1}
//     below it, and word k is the top bit of a_{k-1}. Word k of V_{k-1} is zero.
//
// spec/lean/Spec/RsaMont64Square.lean proves that the rows add up to a^2 and that the rows with
// the multiples of m between them give the multiplication's result. bin/diff_rsa_mont64_square
// holds this function's words to that model (docs/decisions.md 192).
//
// Row i is a round of rsa_mont64_blocks_mul with a_i V_i in place of a_i b. v starts as 2a. Each
// row writes its two words, word i and word i + 1, before it runs, and writes zero to word i
// after it. The last row writes word k - 1, and zero to word k. After the last row the sum is
// (a^2 + U m) / R, for the one U below R that makes a^2 + U m a multiple of R. These are the
// words that rsa_mont64_blocks_mul(o, a, a, mod) writes, below 2m.
//
// The blocks read a_i and u through volatile pointers, as in the multiplication. square_row
// reads v[k] the same way, for the reason rsa_mont64_mont_square reads its top bit that way. v
// holds 2a, which is as secret as a, and the wipe below covers it. Both arrays start at zero
// through memset, as the multiplication's does, which clang-tidy's analyzer reads as a value for
// each word a block loads.
uint64_t rsa_mont64_blocks_square(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    uint64_t v[WORDS_MAX + 1];
    uint64_t t[WORDS_MAX + 2];
    memset(v, 0, (k + 1) * sizeof(uint64_t));
    memset(t, 0, (k + 2) * sizeof(uint64_t));
    uint64_t moved = 0;
    for (size_t j = 0; j < k; j++) {
        v[j] = (a[j] << 1) | moved;
        moved = a[j] >> 63;
    }
    v[k] = moved;
    volatile uint64_t *u = &t[k + 1];
    for (size_t i = 0; i + 1 < k; i++) {
        v[i] = a[i];
        v[i + 1] = a[i + 1] << 1;
        square_row(t, i, &a[i], v, u, mod);
        v[i] = 0;
    }
    v[k - 1] = a[k - 1];
    v[k] = 0;
    square_row(t, k - 1, &a[k - 1], v, u, mod);
    uint64_t top = t[k];
    memcpy(o, t, k * sizeof(uint64_t));
    // t held the running sum and the last row's u, and v held 2a, as secret as a.
    ct_wipe(t, (k + 2) * sizeof(uint64_t));
    ct_wipe(v, (k + 1) * sizeof(uint64_t));
    return top;
}

// The last subtraction (rsa_mont64_blocks.h, docs/decisions.md 209). rsa_mont64.c's reduce_once
// compares in one pass and subtracts under a mask in a second, and in each pass a word waits
// two instructions on the carry of the word below. Here one pass writes a - m to o. A block
// adds four words of a to the complement of four words of m down one carry chain, and the carry
// from the block below down another, as rsa_mont64_block_add's two chains go. The first carry
// in is the one that makes the complement a negation. Eight words and a carry are at most
// 2^257 - 1 together, so at most one of a block's two chains carries out.
//
// The carry out of the top word is 1 when a is at or above m. With top, the word above a, it
// answers whether top:a is at or above m, as rsa_mont64.c's at_or_above answers. A second pass
// keeps a - m under that answer's mask and a under its complement, and no word of it waits on
// another.
//
// Constant time: no branch and no memory index depends on a word. The mask is all ones or all
// zeros, and a compiler that sees how it was computed knows that, and may write a select under
// it as a jump (docs/decisions.md 125). So the mask is written through a volatile pointer and
// read back before the pass uses it, as rsa_sign64.c's table_select reads its masks, and the
// word ends on zero, so no frame keeps the answer. With no read-back, clang for arm64 picked
// with a csel which of the two arrays it loads each word from, an address the answer decides
// (docs/decisions.md 209). A Semgrep rule, inv-16-rsa-blocks-last-subtraction, holds the
// read-back, the last write of zero, and that this function holds no if.
void rsa_mont64_blocks_reduce(uint64_t *o, const uint64_t *a, uint64_t top,
                              const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    const uint64_t *m = mod->m;
    uint64_t carry = 1;
    for (size_t j = 0; j < k; j += 4) {
        ct_u128 sum = (ct_u128)a[j] + ~m[j];
        uint64_t s0 = (uint64_t)sum;
        sum = (ct_u128)a[j + 1] + ~m[j + 1] + (uint64_t)(sum >> 64);
        uint64_t s1 = (uint64_t)sum;
        sum = (ct_u128)a[j + 2] + ~m[j + 2] + (uint64_t)(sum >> 64);
        uint64_t s2 = (uint64_t)sum;
        sum = (ct_u128)a[j + 3] + ~m[j + 3] + (uint64_t)(sum >> 64);
        uint64_t s3 = (uint64_t)sum;
        uint64_t high = (uint64_t)(sum >> 64);
        sum = (ct_u128)s0 + carry;
        o[j] = (uint64_t)sum;
        sum = (ct_u128)s1 + (uint64_t)(sum >> 64);
        o[j + 1] = (uint64_t)sum;
        sum = (ct_u128)s2 + (uint64_t)(sum >> 64);
        o[j + 2] = (uint64_t)sum;
        sum = (ct_u128)s3 + (uint64_t)(sum >> 64);
        o[j + 3] = (uint64_t)sum;
        carry = high + (uint64_t)(sum >> 64);
    }
    // top:a - m borrows when top is zero and a - m borrowed. The sum below carries when it did
    // not: it adds the complement of the zero word above m, and the carry.
    uint64_t at_or_above = (uint64_t)(((ct_u128)top + UINT64_MAX + carry) >> 64);
    uint64_t kept = 0;
    volatile uint64_t *hidden = &kept;
    *hidden = blocks_mask_of_bit(at_or_above);
    uint64_t mask = *hidden;
    for (size_t j = 0; j < k; j++) {
        o[j] = (o[j] & mask) | (a[j] & ~mask);
    }
    *hidden = 0;
}

#endif // RSA_MONT64_BLOCKS
#endif // CH_CPU_RUNTIME
