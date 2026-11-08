// RSA's Montgomery multiplication and square in blocks of four words, which a host object
// built by clang for arm64 runs for a word count that is a multiple of 4 (RSA_MONT64_BLOCKS in
// rsa_mont64.h, docs/decisions.md 118). rsa_mont64.c calls them for its multiplication and its
// square and takes the last subtraction itself.
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

// o and the word returned = a * b / R, plus m or nothing: a Montgomery product before its last
// subtraction. The value is below 2m, so the word returned is 0 or 1. It needs b below m,
// mod->words a multiple of 4, and o apart from a and b.
uint64_t rsa_mont64_blocks_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                               const rsa_mont64_modulus *mod);

// The same for a * a, for a below m: row i adds a_i times the words of a above it, doubled, and
// a_i^2, and in the same pass the row's multiple of m. It writes the words
// rsa_mont64_blocks_mul(o, a, a, mod) writes.
uint64_t rsa_mont64_blocks_square(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod);

// The largest word count whose square rsa_mont64.c runs as rsa_mont64_blocks_mul(o, a, a, mod)
// rather than as rsa_mont64_blocks_square. Both write the same words. On the M1 Pro under Apple
// clang 21 the square took 1.09 times the multiplication's cycles at 16 words, 0.96 at 24, 0.91
// at 32, 0.87 at 48 and 0.84 at 64 (docs/decisions.md 192).
#define RSA_MONT64_SQUARE_AS_MUL_WORDS_MAX 16

#endif // RSA_MONT64_BLOCKS
#endif // CH_CPU_RUNTIME

#endif
