// P-256 points for a host object's ECDSA verifier, on p256_wide_field.c's
// four 64-bit words: the sum u1*G + u2*Q a verification computes, and the
// comparison of that sum's x with r. A host object (-DCH_CPU_RUNTIME,
// cpu_cfg.h) holds this file beside the constant-time wide files, and its
// one caller is p256_wide_verify.c (docs/decisions.md 104).
//
// Variable time on purpose. Every input is public: the key, the hash and
// the signature travel in the clear, so the branches and the table reads
// below read them freely. No private scalar and no nonce is handed to this
// file: a signature and a key exchange run the constant-time files
// (p256_wide_mul.h).
#ifndef CH_P256_WIDE_VERIFY_POINT_H
#define CH_P256_WIDE_VERIFY_POINT_H

#include "p256_point.h"
#include "p256_scalar.h"
#include "p256_wide_field.h"

#ifdef CH_CPU_RUNTIME

// A point in Jacobian coordinates: the affine point (X/Z^2, Y/Z^3), each
// coordinate in the Montgomery domain and below p, and Z = 0 the point at
// infinity.
typedef struct {
    p256_wide_fe x;
    p256_wide_fe y;
    p256_wide_fe z;
} p256_wide_jacobian;

// The key p256_wide_point_from_bytes took, as a Jacobian point. The decoder
// writes the affine coordinates with Z = 1, and with Z = 1 the projective
// point and the Jacobian point are the same point.
void p256_wide_jacobian_from_key(p256_wide_jacobian *o, const p256_point *key);

// o = u1*G + u2*q, for u1 and u2 below n and q a finite point. o may be the
// point at infinity.
void p256_wide_jacobian_double_mul(p256_wide_jacobian *o, const p256_scalar *u1,
                                   const p256_scalar *u2, const p256_wide_jacobian *q);

// 1 when p is the point at infinity.
int p256_wide_jacobian_is_infinity(const p256_wide_jacobian *p);

// 1 when the affine x of sum, reduced modulo n, is r, for a finite sum and
// an r in 1..n-1.
int p256_wide_jacobian_x_is_r(const p256_wide_jacobian *sum, const p256_scalar *r);

#endif // CH_CPU_RUNTIME

#endif
