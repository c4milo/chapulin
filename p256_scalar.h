// Constant-time arithmetic modulo the P-256 group order
// n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
// (SEC 2 secp256r1).
//
// This pair is what p256_field.h names as missing from itself: "The group
// order n has its own Montgomery constants and its own inversion exponent,
// so scalar arithmetic mod n belongs in its own file pair rather than in a
// second modulus argument here." The routines below are the same shape as
// that file's, over a different modulus, and they carry the same contract:
// no branch and no memory index reads a limb, every choice is a mask, and
// every product goes through ct_widemul (ct.h), which builds a 64-bit
// product out of 16x16 pieces because a widening multiply is variable time
// on some cores (https://github.com/c4milo/chapulin/issues/53).
//
// The contract matters more here than in the field. The values this pair
// multiplies and inverts are the ECDSA private key d and the signing nonce
// k. One leaked nonce recovers d outright, so p256.c's arithmetic, which
// branches on its operands because it only ever sees public values
// (p256.h:2-5), must never see either. p256_sign.c calls this file and
// never that one.
//
// No routine here wipes its temporaries; p256_sign.c wipes its own frame
// once, the way x25519.c's ladder does.
#ifndef CH_P256_SCALAR_H
#define CH_P256_SCALAR_H

#include <stdint.h>

#define P256_SCALAR_LIMBS 8 // limb: one 32-bit word of a scalar
#define P256_SCALAR_LEN 32  // bytes in one scalar, big-endian on the wire

// One scalar: eight little-endian 32-bit limbs. Every routine takes
// scalars below n and leaves a scalar below n, unless its own comment
// says otherwise, and the output may be one of the inputs.
typedef struct {
    uint32_t limb[P256_SCALAR_LIMBS];
} p256_scalar;

// Masks follow p256_field.h's convention: a predicate returns 0 for false
// and UINT32_MAX for true, and every routine that chooses between two
// values takes such a mask. Masks are built here out of carry and borrow
// words. Nothing negates a 0-or-1 value, because `0 - bit` is the shape
// gcc rewrites into a multiply by a secret bit
// (https://github.com/c4milo/chapulin/issues/106).

// 0, which is 0 in both domains.
extern const p256_scalar p256_scalar_zero;

// Marshalling. p256_scalar_from_bytes reads 32 big-endian bytes and
// reduces nothing: a value from a key file or from an HMAC output can be
// at or above n, and p256_scalar_reduced_mask is how a caller asks.
void p256_scalar_from_bytes(p256_scalar *o, const uint8_t in[P256_SCALAR_LEN]);
void p256_scalar_to_bytes(uint8_t out[P256_SCALAR_LEN], const p256_scalar *a);

// All ones when a is below n, zero otherwise.
uint32_t p256_scalar_reduced_mask(const p256_scalar *a);
// All ones when a is zero, zero otherwise.
uint32_t p256_scalar_zero_mask(const p256_scalar *a);

// o = a when mask is all ones, o unchanged when mask is zero.
void p256_scalar_cmov(p256_scalar *o, const p256_scalar *a, uint32_t mask);

// o = a mod n for any 256-bit a, reduced or not. One masked conditional
// subtraction of n is enough, because n is above 2^255 and so every
// 256-bit value is below 2n. This is how the message hash becomes z and
// how the x coordinate of k*G becomes r.
void p256_scalar_reduce(p256_scalar *o, const p256_scalar *a);

// o = a + b mod n, and o = a*b mod n. Both take scalars below n and leave
// a scalar below n. The product is a plain product, not a Montgomery one:
// this header states no domain because no caller of it holds a scalar in
// the Montgomery domain. The domain lives inside p256_scalar.c, which
// enters and leaves it within the one call.
void p256_scalar_add(p256_scalar *o, const p256_scalar *a, const p256_scalar *b);
void p256_scalar_mul(p256_scalar *o, const p256_scalar *a, const p256_scalar *b);

// o = a^-1 mod n. a = 0 gives 0, because the exponentiation of zero is
// zero and no branch tests for it; the caller checks a against
// p256_scalar_zero_mask when zero is not an answer it can use. The
// exponent is n-2 (Fermat), a constant of this build, so the sequence of
// squarings and multiplications is the same on every call and reveals
// nothing about a. A binary extended Euclid would be shorter and would
// branch on a, which is the nonce.
void p256_scalar_inverse(p256_scalar *o, const p256_scalar *a);

#endif
