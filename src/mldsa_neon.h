// FIPS 204 Algorithm 30, RejNTTPoly, for two entries of a row of ML-DSA-87's matrix A at once,
// on two Keccak states side by side in NEON (keccak_neon.c). An arm64 host object holds it,
// and mldsa.c's verification and mldsa_sign_steps.c's rows of signing and key generation
// sample A on it in every session (docs/decisions.md 198). On any other target the header
// declares nothing. mld_sample_ntt stays the reference: bin/keccak_neon_equiv_test holds each
// entry to it.
//
// A comes from rho, which pk carries in the clear, and from two indices, so the two streams
// are public. keccak_neon.h states why the two-way Keccak takes public input alone.
#ifndef CH_MLDSA_NEON_H
#define CH_MLDSA_NEON_H

#include <stdint.h>

#include "mldsa_poly.h"

#if defined(CH_CPU_RUNTIME) && defined(__aarch64__)

// The entries of a row that one call samples at most: one to a Keccak state.
#define MLD_NEON_ENTRIES 2

// Entries A[i][first] to A[i][first + count - 1] into e[0] to e[count - 1], each the entry
// mld_sample_ntt samples, for count 1 or 2 and first + count at most MLD_L. Returns 1 when
// each holds 256 coefficients, and 0 when one stops at MLD_SAMPLE_BLOCKS blocks, as
// mld_sample_ntt does. Two entries run on the two-way Keccak, in the form cpu picks
// (keccak_neon_runs_sha3). One entry runs mld_sample_ntt_cpu, which takes less time than two
// states with one unread.
int mld_sample_ntt_neon(uint32_t cpu, mld_poly e[MLD_NEON_ENTRIES],
                        const uint8_t rho[MLD_RHO_BYTES], unsigned i, unsigned first,
                        unsigned count);

// The names the callers of a sampler of several entries read, as mldsa_avx2.h gives them for
// x86-64: the entries one call samples at most, whether a session runs the sampler, and the
// call. Every arm64 CPU has NEON, so every session runs it.
#define MLD_WIDE_ENTRIES MLD_NEON_ENTRIES

static inline int mld_wide_runs(uint32_t cpu) {
    (void)cpu;
    return 1;
}

static inline int mld_sample_ntt_wide(uint32_t cpu, mld_poly e[MLD_WIDE_ENTRIES],
                                      const uint8_t rho[MLD_RHO_BYTES], unsigned i, unsigned first,
                                      unsigned count) {
    return mld_sample_ntt_neon(cpu, e, rho, i, first, count);
}

#endif // CH_CPU_RUNTIME && __aarch64__

#endif
