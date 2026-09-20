// Constant-time P-256 point arithmetic over p256_field.[ch].
//
// p256_field.h names this file's contents as its own callers rather than
// its contents: "Point arithmetic, point validation and the key exchange
// itself are callers, not part of the field." This pair is that caller,
// and it sits between the field and the two files that multiply a secret
// scalar by a point: p256_sign.c, which computes k*G for a signature,
// and p256_ecdh.c, which computes priv*peer for a shared secret. Both
// call p256_point_mul, so the build holds one scalar multiplication and
// one addition formula rather than one of each per caller.
//
// Every routine is constant time in every operand: the trip count is a
// literal, no branch reads a coordinate or a scalar bit, and no memory
// index comes from either. There is no precomputed table, because a table
// indexed by bits of the nonce is exactly the cache leak that recovers an
// ECDSA key. p256_point_from_bytes is the one exception and it says so at
// its own contract: it reads a peer's point, which arrived in the clear.
//
// Coordinates are homogeneous projective (X : Y : Z), standing for the
// affine point (X/Z, Y/Z), with Z = 0 the point at infinity. Every
// coordinate is a p256_fe in the Montgomery domain, because every
// arithmetic step below is a Montgomery product and moving in and out per
// step would cost more than it saves.
#ifndef CH_P256_POINT_H
#define CH_P256_POINT_H

#include <stdint.h>

#include "p256_field.h"
#include "p256_scalar.h"

// One point in SEC 1 section 2.3.3's uncompressed form: the byte 0x04,
// then X, then Y, each 32 bytes big-endian. This is the only encoding
// p256_point_from_bytes reads and the only one p256_point_affine writes.
#define P256_POINT_LEN 65

typedef struct {
    p256_fe x;
    p256_fe y;
    p256_fe z;
} p256_point;

// The point at infinity, (0 : 1 : 0), which is the ladder's starting
// accumulator and the value p256_point_add returns for P + (-P).
extern const p256_point p256_point_infinity;

// secp256r1's generator G, in the Montgomery domain.
extern const p256_point p256_point_generator;

// o = a + b, by the complete addition formula for curves with a = -3
// (Renes, Costello and Batina, EUROCRYPT 2016, Algorithm 4). Complete
// means correct for every pair of inputs, including a = b, a = -b and
// either operand at infinity, so this file has no branch on those cases
// to remove and no separate doubling routine to keep in step. o may alias
// a or b.
//
// test/gen_p256_sign_vectors.py runs the same 43 steps in Python against
// an affine reference, over those cases, before it prints a vector.
void p256_point_add(p256_point *o, const p256_point *a, const p256_point *b);

// Exchanges a and b when mask is all ones, leaves both when it is zero.
// The mask follows p256_field.h's convention.
void p256_point_cswap(p256_point *a, p256_point *b, uint32_t mask);

// o = k*p, over all 256 bits of k, most significant bit first. k is read
// as a 256-bit value, reduced or not; the caller checks the range it
// needs. o may not alias p.
//
// The ladder is Montgomery's. The invariant is r1 = r0 + p: a round
// replaces (r0, r1) with (2*r0, r0+r1) when the bit is 0 and with
// (r0+r1, 2*r1) when it is 1, and two masked exchanges pick between
// them. The bit decides no branch and no index — it becomes a mask and
// nothing else — so the number of rounds, the number of additions and
// the addresses touched are the same for every k and every p. Using the
// complete addition for the doubling costs about a third more field
// multiplications than a dedicated doubling would, and buys the audit
// one formula instead of two.
//
// The three running points hold intermediate multiples of p, which are
// as secret as k. This routine wipes them before it returns, so a caller
// wiping its own frame does not have to know they existed.
void p256_point_mul(p256_point *o, const p256_scalar *k, const p256_point *p);

// o = k*G. This is p256_point_mul against p256_point_generator and
// nothing else: secp256r1's generator gets no precomputed multiples
// here, so a public key costs exactly what a shared secret costs.
void p256_point_base_mul(p256_point *o, const p256_scalar *k);

// Reads an uncompressed point and returns all ones when it is a point
// these routines compute with, zero otherwise: the leading byte is 0x04,
// X and Y are both below the field prime p, and the pair satisfies
// y^2 = x^3 - 3x + b. o holds the point in the Montgomery domain on all
// ones and holds nothing a caller may use on zero.
//
// The two early returns read the peer's bytes, which are public, and
// they are what keeps a coordinate at or above p out of the field
// routines, whose elements are below p.
//
// What this leaves out, and why. The point at infinity has no
// uncompressed encoding — SEC 1 section 2.3.3 gives it the single byte
// 0x00 — and (0, 0) does not satisfy the curve equation, so both fail
// above. Subgroup membership is not checked and does not need to be:
// secp256r1 has prime order and cofactor 1, so every point that
// satisfies the curve equation generates the whole group.
uint32_t p256_point_from_bytes(p256_point *o, const uint8_t in[P256_POINT_LEN]);

// Writes a's affine coordinates as 32 big-endian bytes each, and returns
// all ones when a is a finite point and zero when a is the point at
// infinity. y may be NULL for a caller that wants X alone.
//
// Both outputs are written either way: the infinity case writes the
// bytes the arithmetic produced from a zero inverse, which are not a
// coordinate, and the mask is how the caller learns to discard them.
uint32_t p256_point_affine(uint8_t x[P256_FE_LEN], uint8_t y[P256_FE_LEN], const p256_point *a);

// p256_point_affine with no Y, for the two callers that read only X: the
// signature's r and the ECDH shared secret.
uint32_t p256_point_affine_x(uint8_t out[P256_FE_LEN], const p256_point *a);

#endif
