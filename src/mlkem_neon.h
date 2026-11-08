// FIPS 203 Algorithm 7, SampleNTT, for two entries of a row of ML-KEM's matrix at once, on
// two Keccak states side by side in NEON (keccak_neon.c). An arm64 host object holds it, and
// mlkem.c's mlk_matvec_row samples each pair of a row's entries on it, in mlkem.c under its
// own names and in mlkem_hw.c, the copy on the SHA-3 instructions (docs/decisions.md 198). On
// any other target the header declares nothing. mlk_sample_ntt stays the reference:
// bin/keccak_neon_equiv_test holds each entry to it.
//
// The matrix comes from the seed rho, which the encapsulation key carries in the clear, and
// from two indices, so the two streams are public. keccak_neon.h states why the two-way Keccak
// takes public input alone.
#ifndef CH_MLKEM_NEON_H
#define CH_MLKEM_NEON_H

#include <stdint.h>

#include "mlkem_poly.h"

#if defined(CH_CPU_RUNTIME) && defined(__aarch64__)

// The entries one call samples: one to a Keccak state.
#define MLK_NEON_ENTRIES 2

// Entries first and first + 1 of row i of A, or of A^T where transposed is 1, into e[0] and
// e[1], each the entry mlk_sample_ntt samples: FIPS 203 samples A[i][j] from rho || j || i.
// Each stream stops where its entry holds 256 coefficients or where it has given
// MLK_SAMPLE_GROUPS groups, as mlk_sample_ntt's does. cpu picks the form of the permutation
// (keccak_neon_runs_sha3): mlkem.c passes 0, and mlkem_hw.c, whose sessions hold
// CH_CPU_CONSTANT_TIME_SHA3, passes that bit.
void mlk_sample_pair_neon(mlk_poly e[MLK_NEON_ENTRIES], const uint8_t seed[32], unsigned i,
                          int transposed, unsigned first, uint32_t cpu);

#endif // CH_CPU_RUNTIME && __aarch64__

#endif
