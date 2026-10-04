// The two P-256 scalar multiplications over the wide field: p256_point_mul and
// p256_point_base_mul (p256_point.h) on p256_wide_point.c's formulas. A host object
// (-DCH_CPU_RUNTIME, cpu_cfg.h) holds this file beside p256_point.c, and widemul.h runs it for
// a session whose ch_cfg.cpu holds CH_CPU_CONSTANT_TIME_MULTIPLY (docs/decisions.md 89 and
// 94).
//
// Both take and leave p256_point.h's scalar and point, and keep the wide limbs inside the
// call. Both are constant time in the scalar and in the point. Every trip count is a literal.
// Every read of a table scans its whole row and keeps one entry by mask, so no address read
// depends on the scalar. No branch reads a scalar bit or a coordinate. Both wipe every
// multiple of the point they held before they return.
#ifndef CH_P256_WIDE_MUL_H
#define CH_P256_WIDE_MUL_H

#include "p256_point.h"
#include "p256_scalar.h"

#ifdef CH_CPU_RUNTIME

// o = k*p, over all 256 bits of k, as p256_point_mul computes it: k is read as a 256-bit
// value, reduced or not, and p may be any point, the point at infinity among them. It
// computes the eight odd multiples of p up to 15 p, and then for each of the 64 four-bit
// windows of k, most significant first, doubles four times and adds one of them.
void p256_wide_mul(p256_point *o, const p256_scalar *k, const p256_point *p);

// o = k*G, as p256_point_base_mul computes it, for secp256r1's generator G: 64 additions of
// entries of the table of multiples of G (p256_wide_table.h), one for each four-bit window of
// k, and no doubling.
void p256_wide_base_mul(p256_point *o, const p256_scalar *k);

#endif // CH_CPU_RUNTIME

#endif
