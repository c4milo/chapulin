// The scalar steps poly1305_vector.c and poly1305_avx2.c share: the
// product of two numbers modulo 2^130 - 5, from which each path computes
// the powers of r it multiplies by, and the carry that turns five sums of
// products into five words. Both files include this header in a host
// object's native copy alone, where ct_widemul is the native multiply
// (widemul_native.h). poly1305_avx2.c includes it before it turns AVX2 on,
// so neither file's copy of these steps carries an instruction set the
// other's lacks.
#ifndef CH_POLY1305_SCALAR_H
#define CH_POLY1305_SCALAR_H

#include <stdint.h>

#include "ct.h"

// A word holds 26 bits.
#define WORD_MASK 0x3ffffffU

// Five sums below 2^60 carried into h, twice around: after the first
// pass h1 can exceed 2^26, and the second leaves h0, h2, h3 and h4 below
// 2^26 and h1 at most 2^26, inside the bounds poly1305.c's loop keeps.
static void carry_scalar(uint32_t h[5], uint64_t d[5]) {
    d[1] += d[0] >> 26;
    d[2] += d[1] >> 26;
    d[3] += d[2] >> 26;
    d[4] += d[3] >> 26;
    uint64_t h0 = (d[0] & WORD_MASK) + (d[4] >> 26) * 5;
    uint64_t h1 = (d[1] & WORD_MASK) + (h0 >> 26);
    uint32_t h2 = (uint32_t)d[2] & WORD_MASK;
    uint32_t h3 = (uint32_t)d[3] & WORD_MASK;
    uint32_t h4 = (uint32_t)d[4] & WORD_MASK;
    h[0] = (uint32_t)h0 & WORD_MASK;
    h[1] = (uint32_t)h1 & WORD_MASK;
    h2 += (uint32_t)(h1 >> 26);
    h[2] = h2 & WORD_MASK;
    h3 += h2 >> 26;
    h[3] = h3 & WORD_MASK;
    h4 += h3 >> 26;
    h[4] = h4 & WORD_MASK;
    h[0] += (h4 >> 26) * 5;
    h[1] += h[0] >> 26;
    h[0] &= WORD_MASK;
}

// out = left * right modulo 2^130 - 5, for the powers of r, with words of
// at most 2^26 in and out.
static void multiply_scalar(uint32_t out[5], const uint32_t left[5], const uint32_t right[5]) {
    uint32_t s1 = right[1] * 5;
    uint32_t s2 = right[2] * 5;
    uint32_t s3 = right[3] * 5;
    uint32_t s4 = right[4] * 5;
    uint64_t d[5];
    d[0] = ct_widemul(left[0], right[0]) + ct_widemul(left[1], s4) + ct_widemul(left[2], s3) +
           ct_widemul(left[3], s2) + ct_widemul(left[4], s1);
    d[1] = ct_widemul(left[0], right[1]) + ct_widemul(left[1], right[0]) + ct_widemul(left[2], s4) +
           ct_widemul(left[3], s3) + ct_widemul(left[4], s2);
    d[2] = ct_widemul(left[0], right[2]) + ct_widemul(left[1], right[1]) +
           ct_widemul(left[2], right[0]) + ct_widemul(left[3], s4) + ct_widemul(left[4], s3);
    d[3] = ct_widemul(left[0], right[3]) + ct_widemul(left[1], right[2]) +
           ct_widemul(left[2], right[1]) + ct_widemul(left[3], right[0]) + ct_widemul(left[4], s4);
    d[4] = ct_widemul(left[0], right[4]) + ct_widemul(left[1], right[3]) +
           ct_widemul(left[2], right[2]) + ct_widemul(left[3], right[1]) +
           ct_widemul(left[4], right[0]);
    carry_scalar(out, d);
}

#endif
