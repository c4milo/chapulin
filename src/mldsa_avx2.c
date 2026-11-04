// Contract in mldsa_avx2.h. On any other target this file holds nothing:
// <stdint.h> is here so that it is a translation unit still.
#include <stdint.h>

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)
#include "mldsa_avx2.h"

#include "keccak_avx2.h"

_Static_assert(3 * MLD_SAMPLE_BLOCK_GROUPS == SHAKE128_RATE, "a SHAKE128 block holds whole groups");

// The block state k holds, run through mld_sample_groups into e[k], for
// each of the first count states whose entry does not yet hold 256
// coefficients. Returns how many of the count entries then hold 256.
static unsigned mld_sample_block(mld_poly e[MLD_AVX2_ENTRIES], unsigned have[MLD_AVX2_ENTRIES],
                                 const keccak_x4 *state, unsigned count) {
    uint8_t block[SHAKE128_RATE];
    unsigned sampled = 0;
    for (unsigned k = 0; k < count; k++) {
        if (have[k] < MLD_N) {
            keccak_avx2_block(block, state, k);
            have[k] = mld_sample_groups(&e[k], have[k], block, MLD_SAMPLE_BLOCK_GROUPS);
        }
        sampled += have[k] == MLD_N;
    }
    return sampled;
}

// State k runs the stream of entry first + k, and a state past count runs
// the last entry's stream again, which nothing reads. Each block of each
// stream goes through mld_sample_groups, as each block of mld_sample_ntt's
// stream does, until every entry holds 256 coefficients or its stream has
// given MLD_SAMPLE_BLOCKS blocks. So each entry is the one mld_sample_ntt
// samples. The streams are public, so the loop's branches read nothing
// secret, and nothing here is wiped.
int mld_sample_ntt_avx2(mld_poly e[MLD_AVX2_ENTRIES], const uint8_t rho[MLD_RHO_BYTES], unsigned i,
                        unsigned first, unsigned count) {
    keccak_x4 state;
    uint8_t x0[MLD_AVX2_ENTRIES];
    uint8_t x1[MLD_AVX2_ENTRIES];
    unsigned have[MLD_AVX2_ENTRIES] = {0};
    for (unsigned k = 0; k < MLD_AVX2_ENTRIES; k++) {
        x0[k] = (uint8_t)(first + (k < count ? k : count - 1));
        x1[k] = (uint8_t)i;
    }
    keccak_avx2_shake128_start(&state, rho, x0, x1);
    unsigned sampled = mld_sample_block(e, have, &state, count);
    for (unsigned n = 1; n < MLD_SAMPLE_BLOCKS && sampled < count; n++) {
        keccak_avx2_permute(&state);
        sampled = mld_sample_block(e, have, &state, count);
    }
    return sampled == count;
}

#endif // CH_CPU_RUNTIME && __x86_64__
