// FIPS 204 Algorithm 30, RejNTTPoly, for up to four entries of a row of
// ML-DSA-87's matrix A at once, on four Keccak states side by side in AVX2
// (keccak_avx2.c). An x86-64 host object holds it, and mldsa.c's
// verification and mldsa_sign_steps.c's rows of signing and key generation
// sample A on it for a session whose ch_cfg.cpu holds CH_CPU_AVX2
// (docs/decisions.md 178). On any other target the header declares
// nothing. mld_sample_ntt stays the reference: bin/mldsa_avx2_equiv_test
// holds each entry to it on a CPU that has AVX2.
//
// A comes from rho, which pk carries in the clear, and from two indices,
// so the four streams are public. keccak_avx2.h states why the four-way
// Keccak takes public input alone.
#ifndef CH_MLDSA_AVX2_H
#define CH_MLDSA_AVX2_H

#include <stdint.h>

#include "mldsa_poly.h"

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

// The entries of a row that one call samples at most: one to a Keccak
// state.
#define MLD_AVX2_ENTRIES 4

// Entries A[i][first] to A[i][first + count - 1] into e[0] to
// e[count - 1], each the entry mld_sample_ntt samples, for count from 1 to
// MLD_AVX2_ENTRIES and first + count at most MLD_L. Returns 1 when each
// holds 256 coefficients, and 0 when one stops at MLD_SAMPLE_BLOCKS
// blocks, as mld_sample_ntt does.
//
// Requires: a CPU with AVX2. The callers decide that from the session's
// CH_CPU_AVX2 bit; on a CPU without AVX2 the first instruction faults.
int mld_sample_ntt_avx2(mld_poly e[MLD_AVX2_ENTRIES], const uint8_t rho[MLD_RHO_BYTES], unsigned i,
                        unsigned first, unsigned count);

#endif // CH_CPU_RUNTIME && __x86_64__

#endif
