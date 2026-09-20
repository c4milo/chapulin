// Constant-time arithmetic modulo the NIST P-256 field prime
// p = 2^256 - 2^224 + 2^192 + 2^96 - 1 (SEC 2 secp256r1).
//
// p256.c holds the same arithmetic and must not be called from here.
// That file verifies signatures, where the peer's key, the transcript
// hash and the signature are all public, so its Montgomery multiply
// branches on its operands and its conditional subtractions are `if`
// statements. This pair is for the side that holds a secret: the ECDH
// private scalar and, later, the ECDSA signing nonce. Every routine
// below runs the same instruction sequence whatever the operand values
// are. No branch and no memory index reads a limb, every choice is mask
// arithmetic, and every product goes through ct_widemul (ct.h), which
// builds a 64-bit product out of 32-to-32 multiplies because a widening
// multiply is variable time on some cores
// (https://github.com/c4milo/chapulin/issues/53).
//
// No routine here wipes its temporaries. One point multiplication calls
// these thousands of times, so a wipe per call would cost more than the
// stack words are worth; x25519.c does the same, and its ladder calls
// ct_wipe once at the end. The caller that owns the secret wipes its own
// state that way.
//
// What this pair does not hold. The group order n has its own Montgomery
// constants and its own inversion exponent, so scalar arithmetic mod n
// belongs in its own file pair rather than in a second modulus argument
// here. Point arithmetic, point validation and the key exchange itself
// are callers, not part of the field.
#ifndef CH_P256_FIELD_H
#define CH_P256_FIELD_H

#include <stdint.h>

#define P256_FE_LIMBS 8 // limb: one 32-bit word of a field element
#define P256_FE_LEN 32  // bytes in one field element, big-endian on the wire

// One field element: eight little-endian 32-bit limbs. Every routine
// takes elements below p and leaves an element below p, unless its own
// comment says otherwise, and the output may be one of the inputs.
typedef struct {
    uint32_t limb[P256_FE_LIMBS];
} p256_fe;

// Masks. A predicate here returns 0 for false and UINT32_MAX for true,
// and every routine that chooses between two values takes such a mask.
// The convention is not decoration: a caller that turned a 0-or-1 answer
// into a mask with `0 - bit` would write the shape gcc's match.pd
// rewrites as `bit * x`, a widening multiply by a secret bit
// (ct.h, https://github.com/c4milo/chapulin/issues/106). Masks are made
// in this file, out of carry and borrow words, and passed on.

// The Montgomery domain. R is 2^256. A value a stands in the domain as
// a*R mod p, and p256_fe_mul computes x*y/R mod p, so the product of two
// domain values is again a domain value. p256_fe_to_mont and
// p256_fe_from_mont move a value in and out. Add, subtract, negate,
// cmov, cswap and the predicates read the same in both domains, because
// each is linear in R. Multiply, square and inverse are the routines
// that need the domain stated, and each states it.

// 0, which is 0 in both domains.
extern const p256_fe p256_fe_zero;
// R mod p: the Montgomery form of 1, and the starting accumulator for
// any Montgomery-domain product chain.
extern const p256_fe p256_fe_one_mont;

// Marshalling. p256_fe_from_bytes reads 32 big-endian bytes, the wire
// and SEC 1 order, into limbs and reduces nothing: an element from a
// peer can be at or above p, and p256_fe_reduced_mask is how a caller
// asks. p256_fe_to_bytes writes the 32 big-endian bytes back.
void p256_fe_from_bytes(p256_fe *o, const uint8_t in[P256_FE_LEN]);
void p256_fe_to_bytes(uint8_t out[P256_FE_LEN], const p256_fe *a);

// All ones when a is below p, zero otherwise. A caller that decoded a
// peer's coordinate checks this before using it: the routines below are
// correct only for elements below p.
uint32_t p256_fe_reduced_mask(const p256_fe *a);
// All ones when a is zero, zero otherwise.
uint32_t p256_fe_zero_mask(const p256_fe *a);
// All ones when a and b are the same element, zero otherwise. Both must
// already be below p; this compares limbs, it does not reduce.
uint32_t p256_fe_equal_mask(const p256_fe *a, const p256_fe *b);

// o = a when mask is all ones, o unchanged when mask is zero.
void p256_fe_cmov(p256_fe *o, const p256_fe *a, uint32_t mask);
// Exchanges a and b when mask is all ones, leaves both when mask is
// zero. A scalar's bit is the mask a ladder passes here.
void p256_fe_cswap(p256_fe *a, p256_fe *b, uint32_t mask);

// o = a + b mod p, o = a - b mod p, o = -a mod p (and 0 for a = 0).
void p256_fe_add(p256_fe *o, const p256_fe *a, const p256_fe *b);
void p256_fe_sub(p256_fe *o, const p256_fe *a, const p256_fe *b);
void p256_fe_neg(p256_fe *o, const p256_fe *a);

// o = a*b/R mod p, the Montgomery product. Two domain values give their
// domain product; one domain value and one plain value give the plain
// product.
void p256_fe_mul(p256_fe *o, const p256_fe *a, const p256_fe *b);
// o = a*a/R mod p. This calls p256_fe_mul with both operands the same,
// so it costs a full multiply; it exists because a squaring reads as a
// squaring at the call site, and because a squaring-only routine can be
// written later without touching a caller.
void p256_fe_sqr(p256_fe *o, const p256_fe *a);

// o = a*R mod p, and o = a/R mod p: into the domain and back out.
void p256_fe_to_mont(p256_fe *o, const p256_fe *a);
void p256_fe_from_mont(p256_fe *o, const p256_fe *a);

// o = a^-1, both in the Montgomery domain: given a*R mod p it writes
// a^-1*R mod p. a = 0 gives 0, because the exponentiation of zero is
// zero and no branch tests for it. The exponent is p-2 (Fermat), a
// constant of this build, so the instruction sequence is the same for
// every call and reveals nothing about a.
void p256_fe_inv(p256_fe *o, const p256_fe *a);

#endif
