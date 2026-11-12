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

#include <immintrin.h>

#include "keccak_avx2.h"
#include "mlkem_poly.h"
#include "mlkem_rejection_table.h"

#define CH_MLKEM_AVX2_COPY
static void mlk_matvec_row(mlk_poly *out, const uint8_t seed[32], unsigned i, int transposed,
                           const mlk_polyvec *s, unsigned rank);

// After the renames, so they apply to every declaration the source includes. mlkem.h declares
// each _avx2 name this copy defines for the callers that read it, so a definition here that
// differs from that declaration stops the compile.
#include "mlkem.c"

// One SHAKE128 block holds 56 three-byte groups, so a stream's tenth block
// carries the last 8 of the MLK_SAMPLE_GROUPS that mlk_sample_ntt reads at
// most.
#define MLK_BLOCK_GROUPS 56
_Static_assert(3 * MLK_BLOCK_GROUPS == SHAKE128_RATE, "a SHAKE128 block holds whole groups");

_Static_assert(MLKEM_K_MAX <= 4, "a row's entries fit the four Keccak states");

// Whether each of the row's rank entries holds its 256 coefficients.
static int mlk_row_sampled(const unsigned count[MLKEM_K_MAX], unsigned rank) {
    int sampled = 1;
    for (unsigned j = 0; j < rank; j++) {
        sampled = sampled && count[j] == 256;
    }
    return sampled;
}

// Every function from here to the pop below carries the target attribute
// that turns AVX2 on, as in keccak_avx2.c: clang applies it through one
// attribute push, and gcc's target pragma sets it for each function defined
// after it, until the pop.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx2"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx2")
#endif

// The 16 candidates of the eight groups at buf, candidate i in 16-bit lane
// i, in the order mlk_sample_groups reads them: d1 and then d2 of each
// group. The two loads read the 24 bytes of the groups and no other: bytes
// 0 to 15, and bytes 8 to 23, whose bytes 4 to 15 hold groups 4 to 7. In
// each 128-bit half, VPSHUFB writes bytes 3g and 3g + 1 of group g into the
// lane of d1 and bytes 3g + 1 and 3g + 2 into the lane of d2, the first
// byte low. The low 12 bits of the first lane are d1 = b0 | (b1 & 0x0f) << 8,
// and the high 12 bits of the second are d2 = b1 >> 4 | b2 << 4.
static inline __m256i mlk_candidates(const uint8_t *buf) {
    const __m256i order = _mm256_setr_epi8(0, 1, 1, 2, 3, 4, 4, 5, 6, 7, 7, 8, 9, 10, 10, 11, 4, 5,
                                           5, 6, 7, 8, 8, 9, 10, 11, 11, 12, 13, 14, 14, 15);
    __m128i first = _mm_loadu_si128((const __m128i *)(const void *)buf);
    __m128i second = _mm_loadu_si128((const __m128i *)(const void *)(buf + 8));
    __m256i pairs = _mm256_shuffle_epi8(
        _mm256_inserti128_si256(_mm256_castsi128_si256(first), second, 1), order);
    __m256i low = _mm256_and_si256(pairs, _mm256_set1_epi16(0x0fff));
    __m256i high = _mm256_srli_epi16(pairs, 4);
    // Immediate 0xaa takes the odd lanes of each half from high.
    return _mm256_blend_epi16(low, high, 0xaa);
}

// The candidates of one half of mlk_candidates whose bits are set in kept
// stored from coefficient j of p on, in their order, and j moved past them.
// The store writes eight lanes, zeros after the kept ones, so j is at most
// MLKEM_N - 8.
static inline unsigned mlk_keep(mlk_poly *p, unsigned j, __m128i candidates, unsigned kept) {
    __m128i order = _mm_loadu_si128((const __m128i *)(const void *)MLK_REJECTION_ORDER[kept]);
    _mm_storeu_si128((__m128i *)(void *)&p->coeffs[j], _mm_shuffle_epi8(candidates, order));
    return j + MLK_REJECTION_COUNT[kept];
}

// mlk_sample_groups on AVX2: it keeps the candidates mlk_sample_groups keeps,
// in its order, and returns the same count (docs/decisions.md 225). Eight
// groups a step, while 16 coefficients more fit in p: the 16 candidates go
// in two halves of eight, and VPCMPGTW marks each below q. VPACKSSWB writes
// each half's eight marks as bytes, and VPMOVMSKB takes one bit of each, so
// bits 0 to 7 hold the first half's marks and bits 16 to 23 the second's.
// mlk_sample_groups reads the groups that are left, one at a time. A step
// writes zeros past the coefficients it keeps, so where fewer than 256 are
// kept, the coefficients from the count on are not the ones p held before
// the call. Every branch and every table index here reads candidates of
// the public seed rho, and nothing here holds a secret.
unsigned mlk_sample_groups_avx2(mlk_poly *p, unsigned j, const uint8_t *buf, size_t groups) {
    const __m256i q = _mm256_set1_epi16(MLKEM_Q);
    size_t group = 0;
    for (; group + 8 <= groups && j <= MLKEM_N - 16; group += 8) {
        __m256i candidates = mlk_candidates(buf + 3 * group);
        __m256i below = _mm256_cmpgt_epi16(q, candidates);
        unsigned marks = (unsigned)_mm256_movemask_epi8(_mm256_packs_epi16(below, below));
        j = mlk_keep(p, j, _mm256_castsi256_si128(candidates), marks & 0xffU);
        j = mlk_keep(p, j, _mm256_extracti128_si256(candidates, 1), (marks >> 16) & 0xffU);
    }
    return mlk_sample_groups(p, j, buf + 3 * group, groups - group);
}

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif

// The first groups groups of the block each of the first rank states
// holds, run through mlk_sample_groups_avx2 into the entry whose stream
// the state runs, for each entry that does not yet hold 256 coefficients.
static void mlk_sample_block(mlk_polyvec *a, unsigned count[MLKEM_K_MAX], const keccak_x4 *state,
                             size_t groups, unsigned rank) {
    uint8_t block[SHAKE128_RATE];
    for (unsigned j = 0; j < rank; j++) {
        if (count[j] < 256) {
            keccak_avx2_block(block, state, j);
            count[j] = mlk_sample_groups_avx2(&a->vec[j], count[j], block, groups);
        }
    }
}

// The rank entries of row i of A, or of A^T where transposed is 1, into
// a->vec. Each entry's SHAKE128 stream runs on one of four Keccak states
// side by side. Under ML-KEM-768 the fourth state runs the third entry's
// stream again, and nothing reads it. Each block of each stream goes through
// mlk_sample_groups, as each chunk of mlk_sample_ntt's stream does, until
// every entry holds 256 coefficients or its stream has given
// MLK_SAMPLE_GROUPS groups, the cap mlk_sample_ntt reads under. So each
// entry is the one mlk_sample_ntt samples. The streams come from the public
// seed, so the loop's branches read nothing secret, and nothing here is
// wiped.
static void mlk_sample_row(mlk_polyvec *a, const uint8_t seed[32], unsigned i, int transposed,
                           unsigned rank) {
    keccak_x4 state;
    uint8_t x0[4];
    uint8_t x1[4];
    unsigned count[MLKEM_K_MAX] = {0};
    for (unsigned j = 0; j < 4; j++) {
        unsigned entry = j < rank ? j : rank - 1;
        x0[j] = transposed ? (uint8_t)i : (uint8_t)entry;
        x1[j] = transposed ? (uint8_t)entry : (uint8_t)i;
    }
    keccak_avx2_shake128_start(&state, seed, x0, x1);
    for (size_t read = 0; read < MLK_SAMPLE_GROUPS && !mlk_row_sampled(count, rank);
         read += MLK_BLOCK_GROUPS) {
        if (read > 0) {
            keccak_avx2_permute(&state);
        }
        size_t groups = MLK_SAMPLE_GROUPS - read;
        if (groups > MLK_BLOCK_GROUPS) {
            groups = MLK_BLOCK_GROUPS;
        }
        mlk_sample_block(a, count, &state, groups, rank);
    }
}

// mlkem.c's mlk_matvec_row with the row's rank entries sampled first,
// side by side: out = row i of A o s, or of A^T o s where transposed is 1. The
// entries are public. prod holds products of a public matrix entry with
// the secret vector, so it is wiped.
static void mlk_matvec_row(mlk_poly *out, const uint8_t seed[32], unsigned i, int transposed,
                           const mlk_polyvec *s, unsigned rank) {
    mlk_polyvec a;
    mlk_poly prod;
    mlk_sample_row(&a, seed, i, transposed, rank);
    for (unsigned j = 0; j < rank; j++) {
        mlk_multiply_ntts(&prod, &a.vec[j], &s->vec[j]);
        if (j == 0) {
            *out = prod;
        } else {
            mlk_add(out, out, &prod);
        }
    }
    ct_wipe(&prod, sizeof prod);
}

#endif // CH_CPU_RUNTIME && __x86_64__
