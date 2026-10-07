// mlkem.c compiled once more for an x86-64 host object, under the names
// mlkem_avx2.h gives, with each row of ML-KEM's matrix sampled on four
// Keccak states side by side in AVX2 (keccak_avx2.c): the copy a host
// object runs for a session whose ch_cfg.cpu holds CH_CPU_AVX2 (mlkem.h,
// docs/decisions.md 107). On any other target this file holds nothing:
// <stdint.h> is here so that it is a translation unit still.
//
// The copy is mlkem.c's text but for mlk_matvec_row, which mlkem.c leaves
// to it. Its noise, its hashes and its arithmetic run the code mlkem.c
// runs. Only the matrix moves to the four-way Keccak, because the matrix
// alone comes from public input (keccak_avx2.h).
#include <stdint.h>

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)
#include "mlkem_avx2.h"

#include "keccak_avx2.h"
#include "mlkem_poly.h"

#define CH_MLKEM_AVX2_COPY
static void mlk_matvec_row(mlk_poly *out, const uint8_t seed[32], unsigned i, int transposed,
                           const mlk_polyvec *s);

// After the renames, so they apply to every declaration the source includes. mlkem.h declares
// each _avx2 name this copy defines for the callers that read it, so a definition here that
// differs from that declaration stops the compile.
#include "mlkem.c"

// One SHAKE128 block holds 56 three-byte groups, so a stream's tenth block
// carries the last 8 of the MLK_SAMPLE_GROUPS that mlk_sample_ntt reads at
// most.
#define MLK_BLOCK_GROUPS 56
_Static_assert(3 * MLK_BLOCK_GROUPS == SHAKE128_RATE, "a SHAKE128 block holds whole groups");

// Whether each of the row's three entries holds its 256 coefficients.
static int mlk_row_sampled(const unsigned count[3]) {
    return count[0] == 256 && count[1] == 256 && count[2] == 256;
}

// The first groups groups of the block each of the first three states
// holds, run through mlk_sample_groups into the entry whose stream the
// state runs, for each entry that does not yet hold 256 coefficients.
static void mlk_sample_block(mlk_polyvec *a, unsigned count[3], const keccak_x4 *state,
                             size_t groups) {
    uint8_t block[SHAKE128_RATE];
    for (unsigned j = 0; j < 3; j++) {
        if (count[j] < 256) {
            keccak_avx2_block(block, state, j);
            count[j] = mlk_sample_groups(&a->vec[j], count[j], block, groups);
        }
    }
}

// The three entries of row i of A, or of A^T where transposed is 1, into
// a->vec[0..2]. Each entry's SHAKE128 stream runs on one of four Keccak
// states side by side; the fourth runs the third entry's stream again, and
// nothing reads it. Each block of each stream goes through
// mlk_sample_groups, as each chunk of mlk_sample_ntt's stream does, until
// every entry holds 256 coefficients or its stream has given
// MLK_SAMPLE_GROUPS groups, the cap mlk_sample_ntt reads under. So each
// entry is the one mlk_sample_ntt samples. The streams come from the public
// seed, so the loop's branches read nothing secret, and nothing here is
// wiped.
static void mlk_sample_row(mlk_polyvec *a, const uint8_t seed[32], unsigned i, int transposed) {
    keccak_x4 state;
    uint8_t x0[4];
    uint8_t x1[4];
    unsigned count[3] = {0, 0, 0};
    for (unsigned j = 0; j < 3; j++) {
        x0[j] = transposed ? (uint8_t)i : (uint8_t)j;
        x1[j] = transposed ? (uint8_t)j : (uint8_t)i;
    }
    x0[3] = x0[2];
    x1[3] = x1[2];
    keccak_avx2_shake128_start(&state, seed, x0, x1);
    for (size_t read = 0; read < MLK_SAMPLE_GROUPS && !mlk_row_sampled(count);
         read += MLK_BLOCK_GROUPS) {
        if (read > 0) {
            keccak_avx2_permute(&state);
        }
        size_t groups = MLK_SAMPLE_GROUPS - read;
        if (groups > MLK_BLOCK_GROUPS) {
            groups = MLK_BLOCK_GROUPS;
        }
        mlk_sample_block(a, count, &state, groups);
    }
}

// mlkem.c's mlk_matvec_row with the row's three entries sampled first, side
// by side: out = row i of A o s, or of A^T o s where transposed is 1. The
// entries are public. prod holds products of a public matrix entry with
// the secret vector, so it is wiped.
static void mlk_matvec_row(mlk_poly *out, const uint8_t seed[32], unsigned i, int transposed,
                           const mlk_polyvec *s) {
    mlk_polyvec a;
    mlk_poly prod;
    mlk_sample_row(&a, seed, i, transposed);
    for (unsigned j = 0; j < 3; j++) {
        mlk_multiply_ntts(&prod, &a.vec[j], &s->vec[j]);
        if (j == 0) {
            *out = prod;
        } else {
            mlk_poly_add(out, out, &prod);
        }
    }
    ct_wipe(&prod, sizeof prod);
}

#endif // CH_CPU_RUNTIME && __x86_64__
