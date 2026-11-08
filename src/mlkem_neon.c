// Contract in mlkem_neon.h. On any other target than an arm64 host object this file holds
// nothing: <stdint.h> is there through the header, so it is a translation unit still.
#include "mlkem_neon.h"

#if defined(CH_CPU_RUNTIME) && defined(__aarch64__)

#include "keccak_neon.h"

// One SHAKE128 block holds 56 three-byte groups, so a stream's tenth block carries the last 8
// of the MLK_SAMPLE_GROUPS that mlk_sample_ntt reads at most.
#define MLK_BLOCK_GROUPS 56
_Static_assert(3 * MLK_BLOCK_GROUPS == SHAKE128_RATE, "a SHAKE128 block holds whole groups");

// The first groups groups of the block state k holds, run through mlk_sample_groups into
// e[k], for each state whose entry does not yet hold 256 coefficients. Returns how many of the
// two entries then hold 256.
static unsigned mlk_sample_block(mlk_poly e[MLK_NEON_ENTRIES], unsigned count[MLK_NEON_ENTRIES],
                                 const keccak_x2 *state, size_t groups) {
    uint8_t block[SHAKE128_RATE];
    unsigned sampled = 0;
    for (unsigned k = 0; k < MLK_NEON_ENTRIES; k++) {
        if (count[k] < 256) {
            keccak_neon_block(block, state, k);
            count[k] = mlk_sample_groups(&e[k], count[k], block, groups);
        }
        sampled += count[k] == 256;
    }
    return sampled;
}

// Each block of each stream goes through mlk_sample_groups, as each chunk of mlk_sample_ntt's
// stream does, until both entries hold 256 coefficients or the streams have given
// MLK_SAMPLE_GROUPS groups, the cap mlk_sample_ntt reads under. So each entry is the one
// mlk_sample_ntt samples. The streams come from the public seed, so the loop's branches read
// nothing secret, and nothing here is wiped.
void mlk_sample_pair_neon(mlk_poly e[MLK_NEON_ENTRIES], const uint8_t seed[32], unsigned i,
                          int transposed, unsigned first, uint32_t cpu) {
    keccak_x2 state;
    uint8_t x0[MLK_NEON_ENTRIES];
    uint8_t x1[MLK_NEON_ENTRIES];
    unsigned count[MLK_NEON_ENTRIES] = {0};
    for (unsigned k = 0; k < MLK_NEON_ENTRIES; k++) {
        x0[k] = transposed ? (uint8_t)i : (uint8_t)(first + k);
        x1[k] = transposed ? (uint8_t)(first + k) : (uint8_t)i;
    }
    keccak_neon_shake128_start(&state, seed, x0, x1, cpu);
    unsigned sampled = 0;
    for (size_t read = 0; read < MLK_SAMPLE_GROUPS && sampled < MLK_NEON_ENTRIES;
         read += MLK_BLOCK_GROUPS) {
        if (read > 0) {
            keccak_neon_permute_cpu(&state, cpu);
        }
        size_t groups = MLK_SAMPLE_GROUPS - read;
        if (groups > MLK_BLOCK_GROUPS) {
            groups = MLK_BLOCK_GROUPS;
        }
        sampled = mlk_sample_block(e, count, &state, groups);
    }
}

#endif // CH_CPU_RUNTIME && __aarch64__
