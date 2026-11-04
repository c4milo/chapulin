// The table of multiples of secp256r1's generator G that p256_wide_base_mul reads
// (docs/decisions.md 94 and 109). A host object (-DCH_CPU_RUNTIME, cpu_cfg.h) holds it, 86
// KiB of constants, and a device object holds no table: p256_point_base_mul computes k*G with
// its ladder from G alone.
//
// The shape. A 256-bit scalar is 43 windows of six bits, the top one four bits wide, and
// p256_wide_mul.c writes it as 43 odd digits, one for each window, none of them zero: between
// -63 and 63, and between 1 and 15 in the top window. Row i of the table holds what a digit of
// window i can add: the odd multiples 1, 3, ..., 63 of 2^(6i) * G. So entry [i][j] is
// (2j + 1) * 2^(6i) * G, and k*G is 43 additions of one entry each, with no doubling. A negative
// digit adds the entry with Y negated, so the table holds the positive multiples alone. The
// top row holds 32 entries like every other, and a digit reads its first eight.
//
// Each entry is an affine point, X then Y, each coordinate in the Montgomery domain as
// p256_wide_field.h keeps it. No entry is the point at infinity: (2j + 1) * 2^(6i) is an odd
// number below 64 times a power of two, and the group order is a prime above 64.
//
// The table is public: it holds multiples of G and nothing of any key. The index a secret
// scalar gives is what must not show, so p256_wide_mul.c reads every entry of a row and keeps
// one by mask, and no address it reads depends on the scalar.
//
// tools/p256_wide.py writes p256_wide_table.c from SEC 2's G with Python's integers, and
// make lint-p256-wide fails when the file differs from what the script prints.
// bin/p256_equiv_test recomputes every entry from G with p256_point.c and p256_field.c.
#ifndef CH_P256_WIDE_TABLE_H
#define CH_P256_WIDE_TABLE_H

#include "p256_wide_point.h"

#ifdef CH_CPU_RUNTIME

#define P256_WIDE_TABLE_WINDOW_BITS 6 // the bits of the scalar one digit reads
#define P256_WIDE_TABLE_WINDOWS 43    // six-bit windows of a scalar, the top one four bits wide
#define P256_WIDE_TABLE_ENTRIES 32    // odd multiples in one window: 1, 3, ..., 63

extern const p256_wide_affine p256_wide_table[P256_WIDE_TABLE_WINDOWS][P256_WIDE_TABLE_ENTRIES];

#endif // CH_CPU_RUNTIME

#endif
