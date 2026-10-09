// RSA's Montgomery multiplication and square in rows whose carries go down _addcarry_u64 chains
// (rsa_mont64_addcarry.h).
//
// Every sum here wraps nothing. A block adds x * (y3 : y2 : y1 : y0) and a word w to four words
// of the running sum, which is at most (2^64 - 1) * (2^256 - 1) + 2^64 - 1 + 2^256 - 1 =
// 2^320 - 1, as in rsa_mont64_blocks.c: five words hold it, so the word the block returns cannot
// wrap. Each 128-bit sum of a product and one word is at most (2^64 - 1)^2 + 2^64 - 1, below
// 2^128. proof/rsa_mont64_addcarry_sums_harness.c runs both routines with
// --unsigned-overflow-check on, so each of those sums is a property CBMC checks.
//
// Constant time: no branch and no memory index depends on a word. The branches the file
// compiles to are loops over word counts.
#include "rsa_mont64_addcarry.h"

#ifdef CH_CPU_RUNTIME
#if RSA_MONT64_ADDCARRY

#include <string.h>

#include "ct.h"

// The add with carry has two forms, and RSA_MONT64_CARRY names the one a build compiles:
//
//   RSA_MONT64_CARRY_INTRINSIC  x86-64: _addcarry_u64, which every x86-64 CPU runs, so no bit
//                               of ch_cfg.cpu states it. gcc 13 expands a chain of them to ADC
//                               instructions and keeps the carry in the flags between them.
//   RSA_MONT64_CARRY_SUM        any other machine: a 128-bit sum, the same value.
//
// A gcc build for x86-64 is the one object that runs this file, so it reads the intrinsic. The
// harnesses in proof/ name the sum, which CBMC reads, and bin/rsa_addcarry_equiv_test runs the
// form its machine picks against rsa_mont64.c's loops: the sum on arm64 and the intrinsic on
// x86-64, under gcc in CI's check job.
#define RSA_MONT64_CARRY_INTRINSIC 1
#define RSA_MONT64_CARRY_SUM 2
#ifndef RSA_MONT64_CARRY
#ifdef __x86_64__
#define RSA_MONT64_CARRY RSA_MONT64_CARRY_INTRINSIC
#else
#define RSA_MONT64_CARRY RSA_MONT64_CARRY_SUM
#endif
#endif

#if RSA_MONT64_CARRY == RSA_MONT64_CARRY_INTRINSIC
#include <immintrin.h>
#elif RSA_MONT64_CARRY != RSA_MONT64_CARRY_SUM
#error "RSA_MONT64_CARRY names neither form of the add with carry"
#endif

#define WORDS_MAX RSA_MONT64_WORDS_MAX

// The running sum's words. _addcarry_u64 writes through an unsigned long long pointer, and
// uint64_t is unsigned long on x86-64 Linux, so the running sum is an array of this type and
// each chain writes its word in place: gcc 13 kept a local that the intrinsic wrote through in a
// stack slot of its own.
typedef unsigned long long addcarry_word;

// a + b + carry into *out, and the carry out, 0 or 1. carry is 0 or 1.
static inline unsigned char add_carry(unsigned char carry, addcarry_word a, addcarry_word b,
                                      addcarry_word *out) {
#if RSA_MONT64_CARRY == RSA_MONT64_CARRY_INTRINSIC
    return _addcarry_u64(carry, a, b, out);
#else
    ct_u128 sum = (ct_u128)a + b + carry;
    *out = (addcarry_word)sum;
    return (unsigned char)(sum >> 64);
#endif
}

// (t[3] : t[2] : t[1] : t[0]) and the word returned = the four words + *x * (y[3] : ... : y[0])
// + w. Each product takes its own word of t in a 128-bit sum, q_j = x y_j + t_j, which waits on
// nothing but t. One chain then adds w to q_0's low word, q_j's high word to q_(j+1)'s low word,
// and q_3's high word and the chain's carry are the word above. Only that chain waits on the
// carry from the block below.
static inline addcarry_word block_mul_add(addcarry_word *t, const volatile uint64_t *x,
                                          const uint64_t *y, addcarry_word w) {
    ct_u128 q0 = ct_mul128(*x, y[0]) + t[0];
    ct_u128 q1 = ct_mul128(*x, y[1]) + t[1];
    ct_u128 q2 = ct_mul128(*x, y[2]) + t[2];
    ct_u128 q3 = ct_mul128(*x, y[3]) + t[3];
    unsigned char carry = add_carry(0, (addcarry_word)q0, w, &t[0]);
    carry = add_carry(carry, (addcarry_word)q1, (addcarry_word)(q0 >> 64), &t[1]);
    carry = add_carry(carry, (addcarry_word)q2, (addcarry_word)(q1 >> 64), &t[2]);
    carry = add_carry(carry, (addcarry_word)q3, (addcarry_word)(q2 >> 64), &t[3]);
    return (addcarry_word)(q3 >> 64) + carry;
}

// t[0..n) and the word returned = t[0..n) + *x * y[0..n): blocks of four, and then one word at
// a time, as rsa_mont64.c's loops step.
static inline addcarry_word row_mul_add(addcarry_word *t, const volatile uint64_t *x,
                                        const uint64_t *y, size_t n) {
    addcarry_word w = 0;
    size_t j = 0;
    for (; j + 4 <= n; j += 4) {
        w = block_mul_add(t + j, x, y + j, w);
    }
    for (; j < n; j++) {
        ct_u128 sum = ct_mul128(*x, y[j]) + t[j] + w;
        t[j] = (addcarry_word)sum;
        w = (addcarry_word)(sum >> 64);
    }
    return w;
}

// Round i adds a[i] * b at word i of the running sum and then u * m there, as two rows, where u
// is the multiple of m that makes word i zero; rsa_mont64_mont_mul's rounds add the same two
// products and move the sum down a word instead. Here no word moves: t[i .. i + k] holds the
// running sum after round i - 1, below 2m when b is below m, so t[i + k] is 0 or 1, and the
// words below i are zero and no row reads them again. Each row's carry word goes into t at once,
// so that no carry is held across the other row. After the last round t[k .. 2k] holds the
// product before its last subtraction.
//
// u is kept in a word of its own, read through a volatile pointer at each product, for the
// reason rsa_mont64_mont_mul keeps its own in t's last word; t's words are of another type here.
uint64_t rsa_mont64_addcarry_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                                 const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    const uint64_t *m = mod->m;
    addcarry_word t[2 * WORDS_MAX + 1];
    memset(t, 0, (2 * k + 1) * sizeof(addcarry_word));
    uint64_t u_word[1] = {0};
    volatile uint64_t *u = u_word;
    const volatile uint64_t *m0inv = &mod->m0inv;
    for (size_t i = 0; i < k; i++) {
        addcarry_word carry = row_mul_add(t + i, &a[i], b, k);
        ct_u128 top = (ct_u128)t[i + k] + carry;
        t[i + k] = (addcarry_word)top;
        t[i + k + 1] = (addcarry_word)(top >> 64);
        *u = (uint64_t)ct_mul128(t[i], *m0inv);
        carry = row_mul_add(t + i, u, m, k);
        top = (ct_u128)t[i + k] + carry;
        t[i + k] = (addcarry_word)top;
        t[i + k + 1] += (addcarry_word)(top >> 64);
    }
    for (size_t j = 0; j < k; j++) {
        o[j] = t[k + j];
    }
    uint64_t top = t[2 * k];
    // t held a * b and the multiples of m, and u_word the last round's u: as secret as the
    // product.
    ct_wipe(t, (2 * k + 1) * sizeof(addcarry_word));
    ct_wipe(u_word, sizeof u_word);
    return top;
}

// The square of a is the cross products a_i a_j, i < j, each once and doubled, and the squares
// a_i^2: a row for each i adds a_i times the words above it at word 2i + 1, the doubling shifts
// the 2k words up a bit, and the squares go in at words 2i, as rsa_mont64_blocks_square does.
// The sum is a^2 < m^2. Row i of the reduction then adds u_i * m at word i, which makes word i
// zero, and the last k words, below (m^2 + R m) / R < 2m, are the result. A carry out of word
// i + k of row i goes into the word above, which `top` holds until a later row adds it.
uint64_t rsa_mont64_addcarry_square(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    const uint64_t *m = mod->m;
    addcarry_word t[2 * WORDS_MAX];
    memset(t, 0, 2 * k * sizeof(addcarry_word));
    for (size_t i = 0; i + 1 < k; i++) {
        t[i + k] = row_mul_add(t + 2 * i + 1, &a[i], a + i + 1, k - 1 - i);
    }
    addcarry_word carry = 0;
    addcarry_word moved = 0;
    for (size_t i = 0; i < k; i++) {
        const volatile uint64_t *a_word = &a[i];
        ct_u128 square = ct_mul128(*a_word, *a_word);
        addcarry_word low = (t[2 * i] << 1) | moved;
        addcarry_word high = (t[2 * i + 1] << 1) | (t[2 * i] >> 63);
        moved = t[2 * i + 1] >> 63;
        ct_u128 sum = (ct_u128)low + (uint64_t)square + carry;
        t[2 * i] = (addcarry_word)sum;
        sum = (ct_u128)high + (uint64_t)(square >> 64) + (uint64_t)(sum >> 64);
        t[2 * i + 1] = (addcarry_word)sum;
        carry = (addcarry_word)(sum >> 64);
    }
    uint64_t u_word[1] = {0};
    volatile uint64_t *u = u_word;
    const volatile uint64_t *m0inv = &mod->m0inv;
    uint64_t top = 0;
    for (size_t i = 0; i < k; i++) {
        *u = (uint64_t)ct_mul128(t[i], *m0inv);
        addcarry_word w = row_mul_add(t + i, u, m, k);
        ct_u128 sum = (ct_u128)t[i + k] + w + top;
        t[i + k] = (addcarry_word)sum;
        top = (uint64_t)(sum >> 64);
    }
    for (size_t j = 0; j < k; j++) {
        o[j] = t[k + j];
    }
    // t held a^2 and the multiples of m, and u_word the last row's u: as secret as a.
    ct_wipe(t, 2 * k * sizeof(addcarry_word));
    ct_wipe(u_word, sizeof u_word);
    return top;
}

#endif // RSA_MONT64_ADDCARRY
#endif // CH_CPU_RUNTIME
