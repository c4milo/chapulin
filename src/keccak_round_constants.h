// FIPS 202 §3.2.5: the round constants RC[0..23] for iota, one for each
// round of Keccak-f[1600]. sha3.c's permutation reads them, and so do the
// two that a host object holds beside it: sha3_hw.c's, which compiles
// sha3.c once more, and keccak_avx2.c's, which runs four states at once.
// proof/sha3_round_harness.c holds the table to the constants FIPS 202's
// rc(t) generates.
#ifndef CH_KECCAK_ROUND_CONSTANTS_H
#define CH_KECCAK_ROUND_CONSTANTS_H

#include <stdint.h>

static const uint64_t RC[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

#endif
