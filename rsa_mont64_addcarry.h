// RSA's Montgomery multiplication and square in rows of products whose carries go down
// _addcarry_u64 chains, which a host object built by gcc for x86-64 runs at every word count
// (RSA_MONT64_ADDCARRY in rsa_mont64.h, docs/decisions.md 122). rsa_mont64.c calls them for its
// multiplication and its square and takes the last subtraction itself, as it does for
// rsa_mont64_blocks.c.
//
// A row adds a word times the words of a number to the running sum, four words at a time. Each
// of the four products first takes its own word of the running sum in one 128-bit sum, which
// waits on no carry, and one chain of four adds with carry then adds the carry word from the
// block below, the four low words and the high words one word up. gcc 13 keeps that chain in
// the carry flag, where rsa_mont64.c's loops wait on each word's carry before the next product.
//
// The constant-time terms are rsa_mont64.h's: no branch and no memory index depends on a word,
// and the word a row multiplies by is read through a volatile pointer at each product, so that
// no copy of it outlives the product, for the reason rsa_mont64.c's loops read it that way.
#ifndef CH_RSA_MONT64_ADDCARRY_H
#define CH_RSA_MONT64_ADDCARRY_H

#include <stdint.h>

#include "rsa_mont64.h"

#ifdef CH_CPU_RUNTIME
#if RSA_MONT64_ADDCARRY

// o and the word returned = a * b / R, plus m or nothing: a Montgomery product before its last
// subtraction. The value is below 2m, so the word returned is 0 or 1. It needs b below m, and o
// apart from a and b.
uint64_t rsa_mont64_addcarry_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                                 const rsa_mont64_modulus *mod);

// The same for a * a, for a below m: the cross products once, doubled, the squares added, and
// then a pass that takes the multiples of m off.
uint64_t rsa_mont64_addcarry_square(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod);

#endif // RSA_MONT64_ADDCARRY
#endif // CH_CPU_RUNTIME

#endif
