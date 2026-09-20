// Ephemeral Diffie-Hellman over NIST P-256 (SEC 2 secp256r1), the group
// rfc9846.txt:4548-4549 makes a MUST for key exchange.
//
// The private scalar is secret, so every routine below runs the same
// instruction sequence whatever the scalar holds: no branch and no
// memory index reads it, and every choice is mask arithmetic. The
// arithmetic under it is p256_point.[ch] over p256_field.[ch] and
// p256_scalar.[ch], which carry the same rule and which p256_sign.c
// calls too, so one addition formula and one scalar multiplication
// serve both signing and key exchange. p256.c holds a P-256 as well and
// this file calls none of it: that file verifies signatures over public
// inputs, so its multiply and its point addition branch on their
// operands.
//
// Two branches exist here, and each reads a value the caller already
// learns from the return code. p256_ecdh_point_valid's verdict on a
// peer's point is public: the point arrives on the wire. And
// p256_ecdh_keygen's verdict on a draw tells the caller to draw again;
// it reads whether the draw is below n and nothing else about it.
//
// Encoding. A point travels in SEC 1 section 2.3.3's uncompressed form:
// the byte 0x04, then X, then Y, each 32 bytes big-endian. A scalar and
// a shared secret are 32 big-endian bytes. The compressed forms are not
// read, and a peer that sends one is refused.
//
// Cost. One key exchange runs 512 point additions: the ladder takes one
// scalar bit per round, and each round adds and doubles whatever the bit
// is. There is no precomputed multiple of the generator, so a public key
// costs the same as a shared secret. A table would cost the SRAM this
// library does not spend and a masked scan over every entry to read it.
#ifndef CH_P256_ECDH_H
#define CH_P256_ECDH_H

#include <stdint.h>

// P256_SCALAR_LEN and P256_POINT_LEN are the files that own those two
// encodings: a scalar is p256_scalar.h's and a point is p256_point.h's,
// and this file spells neither a second time.
#include "p256_point.h"
#include "p256_scalar.h"

#define P256_SECRET_LEN 32 // the shared X coordinate, big-endian

// Turns 32 drawn bytes into a key pair: priv = draw, pub = draw * G.
// Returns 1, or 0 when the draw is not in [1, n-1] and the caller must
// draw again. A draw is out of range with probability below 2^-32. The
// caller owns the draw, so no ch_rand_bytes call lands in this file,
// which INV-4 requires. On 0 both outputs are zeroed, so a caller that ignores
// the return code publishes no key rather than a wrong one.
int p256_ecdh_keygen(const uint8_t draw[P256_SCALAR_LEN], uint8_t priv[P256_SCALAR_LEN],
                     uint8_t pub[P256_POINT_LEN]);

// Returns 1 when point is a point this file will compute with: the
// leading byte is 0x04, X and Y are both below the field prime p, and
// the pair satisfies y^2 = x^3 - 3x + b.
//
// What that leaves out, and why. The point at infinity has no
// uncompressed encoding — SEC 1 section 2.3.3 gives it the single byte
// 0x00 — and (0, 0) does not satisfy the curve equation, so both fail
// above. Subgroup membership is not checked and does not need to be:
// secp256r1 has prime order and cofactor 1, so every point that
// satisfies the curve equation generates the whole group.
int p256_ecdh_point_valid(const uint8_t point[P256_POINT_LEN]);

// out = the X coordinate of priv * point, the ECDH shared secret of SEC
// 1 section 3.3.1. Returns 1, or 0 when point fails
// p256_ecdh_point_valid, when priv is not in [1, n-1], or when the
// product is the point at infinity, which the two range checks already
// rule out. On 0 out is zeroed.
int p256_ecdh(const uint8_t priv[P256_SCALAR_LEN], const uint8_t point[P256_POINT_LEN],
              uint8_t out[P256_SECRET_LEN]);

#endif
