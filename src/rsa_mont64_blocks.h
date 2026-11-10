// RSA's Montgomery multiplication and square in blocks of four words, which a host object
// built by clang for arm64 runs for a word count that is a multiple of 4 (RSA_MONT64_BLOCKS in
// rsa_mont64.h, docs/decisions.md 118). rsa_mont64.c calls them for its multiplication and its
// square, and then calls the last subtraction, which runs in blocks too (docs/decisions.md 209).
// rsa_mont_division.h's long division runs its steps on the same block for a public modulus
// (docs/decisions.md 208).
//
// A block adds x times four words of y to four words of the running sum. The low halves of the
// four products go down one carry chain and the high halves down another, which clang compiles
// to add-with-carry instructions, where rsa_mont64.c's loops carry one product at a time. The
// constant-time terms are rsa_mont64.h's: no branch and no memory index depends on a word. x is
// read through a volatile pointer once for each block, and a secret y one word at each product,
// so that no copy of either outlives the block, for the reason rsa_mont64.c's loops read the
// word they multiply by that way. The words of the modulus are public and are read through a
// plain pointer.
#ifndef CH_RSA_MONT64_BLOCKS_H
#define CH_RSA_MONT64_BLOCKS_H

#include <stdint.h>

#include "rsa_mont64.h"

#ifdef CH_CPU_RUNTIME
#if RSA_MONT64_BLOCKS

// (t[3] : t[2] : t[1] : t[0]) and the word returned = the four words + x * (y[3] : ... : y[0])
// + w. The low halves of the four products go down one carry chain and the high halves, with w
// below them, down another. The sum is at most 2^320 - 1, so the word returned cannot wrap.
//
// It reads no memory and keeps no copy, so its caller decides how each operand is read.
// rsa_mont64_blocks.c reads a secret operand through a volatile pointer.
// rsa_mont_division.h's long division, whose operands are public, reads its words through
// plain pointers (docs/decisions.md 208).
static inline uint64_t rsa_mont64_block_add(uint64_t t[4], uint64_t x, uint64_t y0, uint64_t y1,
                                            uint64_t y2, uint64_t y3, uint64_t w) {
    ct_u128 p0 = ct_mul128(x, y0);
    ct_u128 p1 = ct_mul128(x, y1);
    ct_u128 p2 = ct_mul128(x, y2);
    ct_u128 p3 = ct_mul128(x, y3);
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

// o and the word returned = a * b / R, plus m or nothing: a Montgomery product before its last
// subtraction. The value is below 2m, so the word returned is 0 or 1. It needs b below m,
// mod->words a multiple of 4, and o apart from a and b.
uint64_t rsa_mont64_blocks_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                               const rsa_mont64_modulus *mod);

// The same for a * a, for a below m: row i adds a_i times the words of a above it, doubled, and
// a_i^2, and in the same pass the row's multiple of m. It writes the words
// rsa_mont64_blocks_mul(o, a, a, mod) writes.
uint64_t rsa_mont64_blocks_square(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod);

// o = top:a - m when the k + 1 word value top:a is at or above m, and a when it is below: the
// last subtraction of a Montgomery product, in blocks of four words. For top:a below 2m the
// result is top:a mod m. It writes the words rsa_mont64_reduce_once_with_top writes, for every
// a, top and m. It needs mod->words a multiple of 4, and o apart from a.
void rsa_mont64_blocks_reduce(uint64_t *o, const uint64_t *a, uint64_t top,
                              const rsa_mont64_modulus *mod);

// The largest word count whose square rsa_mont64.c runs as rsa_mont64_blocks_mul(o, a, a, mod)
// rather than as rsa_mont64_blocks_square. Both write the same words. On the M1 Pro under Apple
// clang 21 the square took 1.09 times the multiplication's cycles at 16 words, 0.96 at 24, 0.91
// at 32, 0.87 at 48 and 0.84 at 64 (docs/decisions.md 192).
#define RSA_MONT64_SQUARE_AS_MUL_WORDS_MAX 16

#endif // RSA_MONT64_BLOCKS
#endif // CH_CPU_RUNTIME

#endif
