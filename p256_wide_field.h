// The wide P-256 field: constant-time arithmetic modulo the NIST P-256 field prime
// p = 2^256 - 2^224 + 2^192 + 2^96 - 1 on four 64-bit words, every product on the 64x64->128
// multiply ct.h names ct_mul128. A host object (-DCH_CPU_RUNTIME, cpu_cfg.h) holds it beside
// p256_field.c's eight 32-bit words, and widemul.h runs the point arithmetic built on it,
// p256_wide_point.c, for a session whose ch_cfg.cpu holds CH_CPU_CONSTANT_TIME_MULTIPLY, the
// caller's statement about the multiply at both widths (docs/decisions.md 89 and 94). A
// session without the bit runs p256_field.c on ct.h's 16x16 decomposition, and a device
// object holds that field alone.
//
// The two fields hold the same numbers. Both keep an element in the Montgomery domain with
// R = 2^256, so an element here is the element p256_field.h describes with its words taken two
// at a time, and p256_wide_fe_from_portable and p256_wide_fe_to_portable move one across by
// copying words. bin/p256_equiv_test holds every routine below to p256_field.c's on the same
// values.
//
// The contract is p256_field.h's. Every routine runs the same instruction sequence whatever
// its operands hold: no branch and no memory index reads a word, and every choice is mask
// arithmetic. Every routine takes elements below p and leaves an element below p, unless its
// own comment says otherwise, and the output may be one of the inputs. No routine wipes its
// temporaries: p256_wide_fe_inv wipes the powers it names, and the caller that owns a secret
// wipes its own state.
#ifndef CH_P256_WIDE_FIELD_H
#define CH_P256_WIDE_FIELD_H

#include <stdint.h>

#include "p256_field.h"

#ifdef CH_CPU_RUNTIME

#define P256_WIDE_FE_WORDS 4 // the 64-bit words of a field element

// One field element: four little-endian 64-bit words.
typedef struct {
    uint64_t word[P256_WIDE_FE_WORDS];
} p256_wide_fe;

// Masks. A predicate here returns 0 for false and UINT64_MAX for true, and every routine that
// chooses between two values takes such a mask. p256_wide_word.h's p256_wide_mask makes one
// from a carry or a borrow.

// R mod p: the Montgomery form of 1.
extern const p256_wide_fe p256_wide_fe_one_mont;

// The same element in the other field's words: word i here is words 2i and 2i + 1 there.
void p256_wide_fe_from_portable(p256_wide_fe *o, const p256_fe *a);
void p256_wide_fe_to_portable(p256_fe *o, const p256_wide_fe *a);

// Marshalling, as p256_fe_from_bytes and p256_fe_to_bytes: 32 big-endian bytes, and
// p256_wide_fe_from_bytes reduces nothing.
void p256_wide_fe_from_bytes(p256_wide_fe *o, const uint8_t in[P256_FE_LEN]);
void p256_wide_fe_to_bytes(uint8_t out[P256_FE_LEN], const p256_wide_fe *a);

// All ones when a is below p, zero otherwise.
uint64_t p256_wide_fe_reduced_mask(const p256_wide_fe *a);
// All ones when a is zero, zero otherwise.
uint64_t p256_wide_fe_zero_mask(const p256_wide_fe *a);
// All ones when a and b are the same element, zero otherwise. Both must be below p.
uint64_t p256_wide_fe_equal_mask(const p256_wide_fe *a, const p256_wide_fe *b);

// o = a when mask is all ones, o unchanged when mask is zero.
void p256_wide_fe_cmov(p256_wide_fe *o, const p256_wide_fe *a, uint64_t mask);

// o = a + b mod p, o = a - b mod p, o = -a mod p (and 0 for a = 0).
void p256_wide_fe_add(p256_wide_fe *o, const p256_wide_fe *a, const p256_wide_fe *b);
void p256_wide_fe_sub(p256_wide_fe *o, const p256_wide_fe *a, const p256_wide_fe *b);
void p256_wide_fe_neg(p256_wide_fe *o, const p256_wide_fe *a);

// o = a*b/R mod p, the Montgomery product, and o = a*a/R mod p.
void p256_wide_fe_mul(p256_wide_fe *o, const p256_wide_fe *a, const p256_wide_fe *b);
void p256_wide_fe_sqr(p256_wide_fe *o, const p256_wide_fe *a);

// o = a*R mod p, and o = a/R mod p: into the domain and back out.
void p256_wide_fe_to_mont(p256_wide_fe *o, const p256_wide_fe *a);
void p256_wide_fe_from_mont(p256_wide_fe *o, const p256_wide_fe *a);

// o = a^-1, both in the Montgomery domain. a = 0 gives 0. The exponent is p-2 (Fermat), and
// the chain of 255 squarings and 12 multiplies that computes it is the same for every a.
void p256_wide_fe_inv(p256_wide_fe *o, const p256_wide_fe *a);

#endif // CH_CPU_RUNTIME

#endif
