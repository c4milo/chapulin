// P-384 points on p384_wide_field.c's six 64-bit limbs, which a host
// object holds (-DCH_CPU_RUNTIME, cpu_cfg.h; docs/decisions.md 97): a
// key's decoding, the sum u1*G + u2*Q an ECDSA verification computes, and
// the comparison of that sum's x with r. Their one caller is
// p384_wide_verify.c. Variable time on purpose — every input is public
// (see p384.h).
#ifndef CH_P384_WIDE_POINT_H
#define CH_P384_WIDE_POINT_H

#include <stdint.h>

#include "p384.h"
#include "p384_wide_field.h"

#ifdef CH_CPU_RUNTIME

// Every coordinate is in the Montgomery domain: the limbs hold the
// coordinate times 2^384 mod p, and are below p.
typedef struct {
    uint64_t x[P384_WIDE_LIMBS];
    uint64_t y[P384_WIDE_LIMBS];
    uint64_t z[P384_WIDE_LIMBS]; // Jacobian: affine (x/z^2, y/z^3); z == 0 is infinity
} p384_wide_point;

// Writes the key at pub, the raw uncompressed point X||Y, as a point and
// returns 1. Returns 0 for a coordinate at or above p or a point off the
// curve, and q then holds no point.
int p384_wide_point_decode(p384_wide_point *q, const uint8_t pub[P384_PUB_LEN]);

// o = u1*G + u2*q, for a q that p384_wide_point_decode wrote and scalars
// below n. o may be the point at infinity.
void p384_wide_double_mul(p384_wide_point *o, const uint64_t u1[P384_WIDE_LIMBS],
                          const uint64_t u2[P384_WIDE_LIMBS], const p384_wide_point *q);

// 1 when p is the point at infinity.
int p384_wide_point_is_infinity(const p384_wide_point *p);

// 1 when the affine x of sum, reduced modulo n, is r. sum is a point
// p384_wide_double_mul wrote and is not the point at infinity, and r is
// in [1, n - 1].
int p384_wide_point_x_is_r(const p384_wide_point *sum, const uint64_t r[P384_WIDE_LIMBS]);

#endif // CH_CPU_RUNTIME

#endif
