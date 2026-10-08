// The inverse modulo an odd modulus below 2^256 on four 64-bit words: Pornin's optimized binary
// GCD (https://eprint.iacr.org/2020/972). p256_wide_field.c inverts field elements with it, and
// p256_wide_scalar.c scalars modulo the group order (docs/decisions.md 115).
//
// The contract is p256_wide_word.h's: the call runs the same instructions whatever y holds. No
// branch and no memory index reads a word of y or of a value computed from it, and every choice
// is a mask. y is secret at every call: a point's Z before its key or its shared secret leaves
// the point, and a signing nonce. So the call wipes every value it names before it returns, and
// widemul.h's p256_wide_wipe_below clears what the compiler kept in stack slots of its own.
#ifndef CH_P256_WIDE_INVERSE_H
#define CH_P256_WIDE_INVERSE_H

#include <stdint.h>

#ifdef CH_CPU_RUNTIME

#define P256_WIDE_INVERSE_WORDS 4 // the 64-bit words of y, of the inverse and of the modulus

// A modulus m: odd and below 2^256, least significant word first, beside -m^-1 mod 2^64, the
// word each Montgomery reduction modulo m multiplies by.
typedef struct {
    uint64_t word[P256_WIDE_INVERSE_WORDS];
    uint64_t negated_inverse;
} p256_wide_modulus;

// o = y^-1 mod m for y below m and coprime to m, and o = 0 for y = 0. o may be y.
void p256_wide_inverse(uint64_t o[P256_WIDE_INVERSE_WORDS],
                       const uint64_t y[P256_WIDE_INVERSE_WORDS], const p256_wide_modulus *m);

#endif // CH_CPU_RUNTIME

#endif
