// Contract in mldsa_neon.h. On any other target than an arm64 host object this file holds
// nothing: <stdint.h> is there through the header, so it is a translation unit still.
#include "mldsa_neon.h"

#if defined(CH_CPU_RUNTIME) && defined(__aarch64__)

#include "keccak_neon.h"

_Static_assert(3 * MLD_SAMPLE_BLOCK_GROUPS == SHAKE128_RATE, "a SHAKE128 block holds whole groups");

// The block state k holds, run through mld_sample_groups into e[k], for each state whose entry
// does not yet hold 256 coefficients. Returns how many of the two entries then hold 256.
static unsigned mld_sample_block(mld_poly e[MLD_NEON_ENTRIES], unsigned have[MLD_NEON_ENTRIES],
                                 const keccak_x2 *state) {
    uint8_t block[SHAKE128_RATE];
    unsigned sampled = 0;
    for (unsigned k = 0; k < MLD_NEON_ENTRIES; k++) {
        if (have[k] < MLD_N) {
            keccak_neon_block(block, state, k);
            have[k] = mld_sample_groups(&e[k], have[k], block, MLD_SAMPLE_BLOCK_GROUPS);
        }
        sampled += have[k] == MLD_N;
    }
    return sampled;
}

// State k runs the stream of entry first + k. Each block of each stream goes through
// mld_sample_groups, as each block of mld_sample_ntt's stream does, until both entries hold
// 256 coefficients or the streams have given MLD_SAMPLE_BLOCKS blocks. So each entry is the
// one mld_sample_ntt samples. The streams are public, so the loop's branches read nothing
// secret, and nothing here is wiped.
int mld_sample_ntt_neon(uint32_t cpu, mld_poly e[MLD_NEON_ENTRIES],
                        const uint8_t rho[MLD_RHO_BYTES], unsigned i, unsigned first,
                        unsigned count) {
    if (count < MLD_NEON_ENTRIES) {
        return mld_sample_ntt_cpu(cpu, &e[0], rho, (uint8_t)first, (uint8_t)i);
    }
    keccak_x2 state;
    const uint8_t x0[MLD_NEON_ENTRIES] = {(uint8_t)first, (uint8_t)(first + 1)};
    const uint8_t x1[MLD_NEON_ENTRIES] = {(uint8_t)i, (uint8_t)i};
    unsigned have[MLD_NEON_ENTRIES] = {0};
    keccak_neon_shake128_start(&state, rho, x0, x1, cpu);
    unsigned sampled = mld_sample_block(e, have, &state);
    for (unsigned n = 1; n < MLD_SAMPLE_BLOCKS && sampled < MLD_NEON_ENTRIES; n++) {
        keccak_neon_permute_cpu(&state, cpu);
        sampled = mld_sample_block(e, have, &state);
    }
    return sampled == MLD_NEON_ENTRIES;
}

#endif // CH_CPU_RUNTIME && __aarch64__
