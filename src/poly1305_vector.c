#include "poly1305_vector.h"

// The whole file compiles only under CH_POLY1305_VECTOR (poly1305_vector.h).
#ifdef CH_POLY1305_VECTOR

#ifdef __ARM_NEON
#include <arm_neon.h>
#include <string.h>
#else
#include <emmintrin.h>
#endif

#include "ch_assert.h"
#include "poly1305_scalar.h"

// The 2^128 bit of a whole block, in its fifth word.
#define HIGH_BIT ((uint32_t)1 << 24)

// The most pairs of blocks a pass takes before its carry: four on NEON
// and two on SSE2, which no x86-64 machine here has timed with four. A
// carry then waits on the products of the pass's first pair alone. The
// sums of 20 products stay below 2^59, which
// spec/lean/Spec/Poly1305Vector.lean proves (docs/decisions.md 194).
#ifdef __ARM_NEON
#define PASS_PAIRS 4
#else
#define PASS_PAIRS 2
#endif
#define PAIR_BYTES ((size_t)32)
#define PASS_BYTES (PASS_PAIRS * PAIR_BYTES)
_Static_assert(PASS_BYTES % POLY1305_VECTOR_GROUP == 0, "a pass is whole groups");

// The vector operations the group loop below is written in, one set per
// instruction set. A words vector holds one 32-bit word in each of two
// lanes, and a sums vector one 64-bit sum of products in each of the same
// two lanes. Every operation acts on both lanes at once and has no branch
// and no memory access that depends on a lane's value.

#ifdef __ARM_NEON

typedef uint32x2_t words;
typedef uint64x2_t sums;

static inline words words_of(uint32_t lane0, uint32_t lane1) {
    return vset_lane_u32(lane1, vdup_n_u32(lane0), 1);
}

static inline words words_add(words a, words b) {
    return vadd_u32(a, b);
}

static inline sums sums_zero(void) {
    return vdupq_n_u64(0);
}

// sum + a * b in each lane, the product widened to 64 bits: UMLAL.
static inline sums sums_multiply_add(sums sum, words a, words b) {
    return vmlal_u32(sum, a, b);
}

// sum + (from >> 26) in each lane: USRA.
static inline sums sums_add_carry(sums sum, sums from) {
    return vsraq_n_u64(sum, from, 26);
}

// sum + (from >> 26) * 5 in each lane, for a carry below 2^32: SHRN, then
// UMLAL by 5. clang turns a shift and an add by the carry into a multiply
// by 5, and NEON has no multiply of 64-bit lanes, so clang moves each lane
// to a general register and back; this form keeps the lanes in place.
static inline sums sums_add_carry_times_5(sums sum, sums from) {
    return vmlal_u32(sum, vshrn_n_u64(from, 26), vdup_n_u32(5));
}

static inline sums sums_low_word(sums a) {
    return vandq_u64(a, vdupq_n_u64(WORD_MASK));
}

// Each lane's low 32 bits, for a sum below 2^32.
static inline words sums_narrow(sums a) {
    return vmovn_u64(a);
}

static inline uint64_t sums_lane_total(sums a) {
    return vgetq_lane_u64(a, 0) + vgetq_lane_u64(a, 1);
}

// The 64-bit word at p, little-endian as poly1305_vector.h requires.
static inline uint64_t load64(const uint8_t *p) {
    uint64_t word;
    memcpy(&word, p, sizeof word);
    return word;
}

// The five words of the block at m in lane 0 and of the block at m + 16
// in lane 1, each with its 2^128 bit. A 64-bit lane holds eight bytes of
// a block, little-endian as poly1305_vector.h requires.
static inline void load_blocks(words out[5], const uint8_t *m) {
    uint64x2_t first = vreinterpretq_u64_u8(vld1q_u8(m));
    uint64x2_t second = vreinterpretq_u64_u8(vld1q_u8(m + 16));
    uint64x2_t low = vcombine_u64(vget_low_u64(first), vget_low_u64(second));
    uint64x2_t high = vcombine_u64(vget_high_u64(first), vget_high_u64(second));
    words mask = vdup_n_u32(WORD_MASK);
    out[0] = vand_u32(vmovn_u64(low), mask);
    out[1] = vand_u32(vshrn_n_u64(low, 26), mask);
    out[2] = vand_u32(vmovn_u64(vorrq_u64(vshrq_n_u64(low, 52), vshlq_n_u64(high, 12))), mask);
    out[3] = vand_u32(vshrn_n_u64(high, 14), mask);
    out[4] = vorr_u32(vmovn_u64(vshrq_n_u64(high, 40)), vdup_n_u32(HIGH_BIT));
}

// load_blocks with the split in the general registers, each pair of words
// moved to a vector in one 64-bit move. The products of a pass of four
// pairs keep the vector units busy, and on the M1 Pro this split took a
// sixth off such passes. A pass of two pairs runs load_blocks, which took
// less time there (docs/decisions.md 194).
static inline void load_blocks_split(words out[5], const uint8_t *m) {
    uint64_t low0 = load64(m);
    uint64_t high0 = load64(m + 8);
    uint64_t low1 = load64(m + 16);
    uint64_t high1 = load64(m + 24);
    uint64_t word0 = (low0 & WORD_MASK) | ((low1 & WORD_MASK) << 32);
    uint64_t word1 = ((low0 >> 26) & WORD_MASK) | (((low1 >> 26) & WORD_MASK) << 32);
    uint64_t word2 = (((low0 >> 52) | (high0 << 12)) & WORD_MASK) |
                     ((((low1 >> 52) | (high1 << 12)) & WORD_MASK) << 32);
    uint64_t word3 = ((high0 >> 14) & WORD_MASK) | (((high1 >> 14) & WORD_MASK) << 32);
    uint64_t word4 = ((high0 >> 40) | HIGH_BIT) | (((high1 >> 40) | HIGH_BIT) << 32);
    out[0] = vcreate_u32(word0);
    out[1] = vcreate_u32(word1);
    out[2] = vcreate_u32(word2);
    out[3] = vcreate_u32(word3);
    out[4] = vcreate_u32(word4);
}

#else

// SSE2's multiply reads the low 32 bits of each 64-bit lane, so a words
// vector keeps each word there, with 0 in the lane's high 32 bits. The
// SSE2 calls take a lane's word as an int; the casts below keep its 32
// bits, which is how gcc and clang define the conversion of a value above
// INT_MAX.
typedef __m128i words;
typedef __m128i sums;

static inline words words_of(uint32_t lane0, uint32_t lane1) {
    return _mm_set_epi32(0, (int)lane1, 0, (int)lane0);
}

static inline words words_add(words a, words b) {
    return _mm_add_epi64(a, b);
}

static inline sums sums_zero(void) {
    return _mm_setzero_si128();
}

// sum + a * b in each lane, the product widened to 64 bits: PMULUDQ.
static inline sums sums_multiply_add(sums sum, words a, words b) {
    return _mm_add_epi64(sum, _mm_mul_epu32(a, b));
}

// sum + (from >> 26) in each lane.
static inline sums sums_add_carry(sums sum, sums from) {
    return _mm_add_epi64(sum, _mm_srli_epi64(from, 26));
}

// sum + (from >> 26) * 5 in each lane, as the carry plus 4 times it.
static inline sums sums_add_carry_times_5(sums sum, sums from) {
    sums carry = _mm_srli_epi64(from, 26);
    return _mm_add_epi64(_mm_add_epi64(sum, carry), _mm_slli_epi64(carry, 2));
}

static inline sums sums_low_word(sums a) {
    return _mm_and_si128(a, _mm_set_epi32(0, (int)WORD_MASK, 0, (int)WORD_MASK));
}

// A sum below 2^32 is already a words vector: its high 32 bits are 0.
static inline words sums_narrow(sums a) {
    return a;
}

// Lane 0 plus lane 1: the high lane added to the low one, and the low
// 64 bits stored.
static inline uint64_t sums_lane_total(sums a) {
    uint64_t total = 0;
    _mm_storel_epi64((__m128i *)(void *)&total, _mm_add_epi64(a, _mm_unpackhi_epi64(a, a)));
    return total;
}

// The five words of the block at m in lane 0 and of the block at m + 16
// in lane 1, each with its 2^128 bit. A 64-bit lane holds eight bytes of
// a block, little-endian as poly1305_vector.h requires.
static inline void load_blocks(words out[5], const uint8_t *m) {
    __m128i first = _mm_loadu_si128((const __m128i *)(const void *)m);
    __m128i second = _mm_loadu_si128((const __m128i *)(const void *)(m + 16));
    __m128i low = _mm_unpacklo_epi64(first, second);
    __m128i high = _mm_unpackhi_epi64(first, second);
    __m128i mask = _mm_set_epi32(0, (int)WORD_MASK, 0, (int)WORD_MASK);
    out[0] = _mm_and_si128(low, mask);
    out[1] = _mm_and_si128(_mm_srli_epi64(low, 26), mask);
    out[2] = _mm_and_si128(_mm_or_si128(_mm_srli_epi64(low, 52), _mm_slli_epi64(high, 12)), mask);
    out[3] = _mm_and_si128(_mm_srli_epi64(high, 14), mask);
    out[4] =
        _mm_or_si128(_mm_srli_epi64(high, 40), _mm_set_epi32(0, (int)HIGH_BIT, 0, (int)HIGH_BIT));
}

#endif

// A power of r in each lane, as poly1305.c's loop holds r: the five words,
// and 5 times each of the four whose products pass 2^130.
typedef struct {
    words r0, r1, r2, r3, r4;
    words s1, s2, s3, s4;
} multiplier;

// How multiply_add reads a multiplier: through a volatile pointer, so a
// product loads its word from the struct where it uses it. A pass's
// multipliers are more vectors than SSE2's 16 registers hold, and a NEON
// pass of four pairs needs 36 beside arm64's 32. A compiler that loads
// them before the loop keeps some in stack slots it picks, which ct_wipe
// cannot name: Apple clang 21 left r^4 there on x86-64, gcc 13 left r^2
// on arm64, and bin/poly1305_equiv_test's residue check found both. Read
// this way, the powers stay in the one struct the call wipes. On the M1
// Pro the reads cost 10% of a call over 16 KiB (docs/decisions.md 83 and
// 194).
typedef const volatile multiplier multiplier_read;

// The power lane0 in lane 0 and the power lane1 in lane 1. Each word is
// at most 2^26, so 5 times it fits in 32 bits.
static void multiplier_set(multiplier *by, const uint32_t lane0[5], const uint32_t lane1[5]) {
    by->r0 = words_of(lane0[0], lane1[0]);
    by->r1 = words_of(lane0[1], lane1[1]);
    by->r2 = words_of(lane0[2], lane1[2]);
    by->r3 = words_of(lane0[3], lane1[3]);
    by->r4 = words_of(lane0[4], lane1[4]);
    by->s1 = words_of(lane0[1] * 5, lane1[1] * 5);
    by->s2 = words_of(lane0[2] * 5, lane1[2] * 5);
    by->s3 = words_of(lane0[3] * 5, lane1[3] * 5);
    by->s4 = words_of(lane0[4] * 5, lane1[4] * 5);
}

// d += a * by in each lane: poly1305.c's five sums of five products. Each
// sum takes a2, a3 and a4 before a0 and a1, because carry below finishes
// h0 and h1 last: each of its rounds adds 5 times a carry to word 0, a
// step more than the other words take, and h1 takes its second carry from
// word 0. So the first three products of a sum need not wait for them.
static inline void multiply_add(sums d[5], const words a[5], multiplier_read *by) {
    d[0] = sums_multiply_add(d[0], a[2], by->s3);
    d[0] = sums_multiply_add(d[0], a[3], by->s2);
    d[0] = sums_multiply_add(d[0], a[4], by->s1);
    d[0] = sums_multiply_add(d[0], a[0], by->r0);
    d[0] = sums_multiply_add(d[0], a[1], by->s4);
    d[1] = sums_multiply_add(d[1], a[2], by->s4);
    d[1] = sums_multiply_add(d[1], a[3], by->s3);
    d[1] = sums_multiply_add(d[1], a[4], by->s2);
    d[1] = sums_multiply_add(d[1], a[0], by->r1);
    d[1] = sums_multiply_add(d[1], a[1], by->r0);
    d[2] = sums_multiply_add(d[2], a[2], by->r0);
    d[2] = sums_multiply_add(d[2], a[3], by->s4);
    d[2] = sums_multiply_add(d[2], a[4], by->s3);
    d[2] = sums_multiply_add(d[2], a[0], by->r2);
    d[2] = sums_multiply_add(d[2], a[1], by->r1);
    d[3] = sums_multiply_add(d[3], a[2], by->r1);
    d[3] = sums_multiply_add(d[3], a[3], by->r0);
    d[3] = sums_multiply_add(d[3], a[4], by->s4);
    d[3] = sums_multiply_add(d[3], a[0], by->r3);
    d[3] = sums_multiply_add(d[3], a[1], by->r2);
    d[4] = sums_multiply_add(d[4], a[2], by->r2);
    d[4] = sums_multiply_add(d[4], a[3], by->r1);
    d[4] = sums_multiply_add(d[4], a[4], by->r0);
    d[4] = sums_multiply_add(d[4], a[0], by->r4);
    d[4] = sums_multiply_add(d[4], a[1], by->r3);
}

// The sums for the pairs of blocks at m, pairs of them: 2 or PASS_PAIRS,
// a constant wherever the function is inlined. Lane 0 takes the first
// block of each pair and lane 1 the second, so each lane runs Horner's
// rule over every other block:
//
//   d = (h + the lane's block of pair 0) * by[0] + ... + (its block of pair k) * by[k]
//
// The pairs after the first go first: they do not wait on h. Every array
// here is indexed by constants once the loops are unrolled: gcc keeps an
// array that a rolled loop indexes in memory, and reloads it on every
// pass. gcc does not expand a macro in the pragma, so the count is written
// out and the assertion holds it.
_Static_assert(PASS_PAIRS <= 4, "each #pragma GCC unroll 4 below covers PASS_PAIRS");

// load_blocks for a pass of pairs pairs: on NEON a pass of four pairs
// splits the blocks in the general registers.
static inline void load_pair(words out[5], const uint8_t *m, size_t pairs) {
#ifdef __ARM_NEON
    if (pairs == 4) {
        load_blocks_split(out, m);
        return;
    }
#else
    (void)pairs;
#endif
    load_blocks(out, m);
}

// pairs_sums is always inlined, so pairs is a constant in each copy and
// clang unrolls its loop: clang did not inline it on its own, and the call
// took a third more time over 16 KiB.
static inline __attribute__((always_inline)) void
pairs_sums(sums d[5], const words h[5], const uint8_t *m, multiplier_read *by, size_t pairs) {
    d[0] = sums_zero();
    d[1] = sums_zero();
    d[2] = sums_zero();
    d[3] = sums_zero();
    d[4] = sums_zero();
#pragma GCC unroll 4
    for (size_t k = pairs - 1; k > 0; k--) {
        words blocks[5];
        load_pair(blocks, m + PAIR_BYTES * k, pairs);
        multiply_add(d, blocks, &by[k]);
    }
    words first[5];
    load_pair(first, m, pairs);
    first[0] = words_add(first[0], h[0]);
    first[1] = words_add(first[1], h[1]);
    first[2] = words_add(first[2], h[2]);
    first[3] = words_add(first[3], h[3]);
    first[4] = words_add(first[4], h[4]);
    multiply_add(d, first, &by[0]);
}

// One round of carries: each value's low 26 bits plus the carry out of
// the value below it, and for value 0 5 times the carry out of value 4,
// because 2^130 is 5 modulo 2^130 - 5. The five adds do not wait on each
// other. Each adds a shifted value to a masked one, so a compiler finds
// no chain of adds to move a carry into.
static inline void carry_round(sums out[5], const sums in[5]) {
    out[0] = sums_add_carry_times_5(sums_low_word(in[0]), in[4]);
    out[1] = sums_add_carry(sums_low_word(in[1]), in[0]);
    out[2] = sums_add_carry(sums_low_word(in[2]), in[1]);
    out[3] = sums_add_carry(sums_low_word(in[3]), in[2]);
    out[4] = sums_add_carry(sums_low_word(in[4]), in[3]);
}

// The five sums of each lane carried into words, in two rounds: values
// below 2^34, then words below 2^26 + 2^10, the bounds and the 32-bit
// carry spec/lean/Spec/Poly1305Vector.lean's passStep_bounds proves.
static inline void carry(words h[5], const sums d[5]) {
    sums once[5];
    sums twice[5];
    carry_round(once, d);
    carry_round(twice, once);
    h[0] = sums_narrow(twice[0]);
    h[1] = sums_narrow(twice[1]);
    h[2] = sums_narrow(twice[2]);
    h[3] = sums_narrow(twice[3]);
    h[4] = sums_narrow(twice[4]);
}

// What one call derives from r: r to r^(2 PASS_PAIRS), and the
// multipliers built from them. r and a tag seen on the wire give the pad
// s, and r and s forge any message under that key, so the call wipes this
// one struct through ct_wipe when it ends. No wipe written in C clears a
// register or a spill slot, which is why multiply_add reads the
// multipliers as multiplier_read says.
typedef struct {
    uint32_t power[2 * PASS_PAIRS][5]; // power[i] is r^(i + 1)
    multiplier by[PASS_PAIRS];
} powers;

// The fewest bytes for which a NEON call runs passes of PASS_PAIRS pairs,
// and computes r^5 to r^8. On the M1 Pro a call of 1,024 bytes took 8%
// more time with them, and one of 2,048 bytes 9% less (docs/decisions.md
// 194). A shorter call, a QUIC packet's among them, takes two pairs.
#define POLY1305_VECTOR_WIDE_MIN ((size_t)2048)

// power[1] to power[2 * pairs - 1] from power[0], which holds r.
static void powers_compute(powers *of_r, size_t pairs) {
    multiply_scalar(of_r->power[1], of_r->power[0], of_r->power[0]);
    multiply_scalar(of_r->power[2], of_r->power[1], of_r->power[0]);
    multiply_scalar(of_r->power[3], of_r->power[1], of_r->power[1]);
#if PASS_PAIRS == 4
    if (pairs == 4) {
        multiply_scalar(of_r->power[4], of_r->power[3], of_r->power[0]);
        multiply_scalar(of_r->power[5], of_r->power[3], of_r->power[1]);
        multiply_scalar(of_r->power[6], of_r->power[3], of_r->power[2]);
        multiply_scalar(of_r->power[7], of_r->power[3], of_r->power[3]);
    }
#else
    (void)pairs;
#endif
}

// The multipliers of the last pairs of by[], from by[PASS_PAIRS - pairs]
// on, for every pass but the last: by[k] multiplies both lanes by
// r^(2 (PASS_PAIRS - k)). With last set, the last pass's: lane 1 of by[k]
// takes r^(2 (PASS_PAIRS - k) - 1), one power less, because its blocks
// come one block after lane 0's. So the last two multipliers of either set
// are those of a pass of two pairs.
static inline void multipliers_write(powers *of_r, size_t pairs, size_t last) {
#pragma GCC unroll 4
    for (size_t k = PASS_PAIRS - pairs; k < PASS_PAIRS; k++) {
        size_t even = 2 * (PASS_PAIRS - k) - 1;
        multiplier_set(&of_r->by[k], of_r->power[even], of_r->power[even - last]);
    }
}

// multipliers_write. On x86-64 the call is never inlined. Inlined into the
// entry, Apple clang 21 kept a copy of r^4's multiplier in a stack slot it
// picked, which ct_wipe cannot name, and bin/poly1305_equiv_test's residue
// check found it. Out of line, it writes the multipliers into the struct
// alone. On arm64 it is inlined: out of line, clang loaded the
// multipliers from the struct in every pass of two pairs, and such a pass
// took 30% more time.
#ifdef __ARM_NEON
static inline void multipliers_set(powers *of_r, size_t pairs, size_t last) {
    multipliers_write(of_r, pairs, last);
}
#else
static __attribute__((noinline)) void multipliers_set(powers *of_r, size_t pairs, size_t last) {
    multipliers_write(of_r, pairs, last);
}
#endif

// The n bytes at m in passes of pairs pairs, a constant wherever the
// function is inlined, from the accumulator in h. On return d holds the
// last pass's sums. A call of an odd count of groups starts with one
// group, two pairs, under the set's last two multipliers, r^4 and r^2.
// Each pass after it but the last multiplies by the set and carries. The
// last pass, or the one group of a call of one group, takes the powers the
// last blocks are owed.
static inline __attribute__((always_inline)) void passes(sums d[5], words h[5], const uint8_t *m,
                                                         size_t n, powers *of_r, size_t pairs) {
    size_t pass_bytes = PAIR_BYTES * pairs;
    multiplier_read *by = &of_r->by[PASS_PAIRS - pairs];
    multiplier_read *two = &of_r->by[PASS_PAIRS - 2];
    multipliers_set(of_r, pairs, 0);
    size_t lead = n % pass_bytes;
    if (lead != 0 && n > lead) {
        pairs_sums(d, h, m, two, 2);
        carry(h, d);
        m += lead;
        n -= lead;
    }
    for (; n > pass_bytes; n -= pass_bytes) {
        pairs_sums(d, h, m, by, pairs);
        carry(h, d);
        m += pass_bytes;
    }
    multipliers_set(of_r, pairs, 1);
    if (n == pass_bytes) {
        pairs_sums(d, h, m, by, pairs);
    } else {
        pairs_sums(d, h, m, two, 2);
    }
}

void poly1305_vector_blocks(poly1305 *p, const uint8_t *m, size_t n) {
    CH_ASSERT(n > 0 && n % POLY1305_VECTOR_GROUP == 0);
    // Only n, which is public, picks the pairs of a pass.
#if PASS_PAIRS > 2
    size_t pairs = n >= POLY1305_VECTOR_WIDE_MIN ? PASS_PAIRS : 2;
#else
    size_t pairs = 2;
#endif
    powers of_r;
    for (size_t i = 0; i < 5; i++) {
        of_r.power[0][i] = p->r[i];
    }
    powers_compute(&of_r, pairs);

    // Lane 0 starts from the accumulator and lane 1 from 0.
    words h[5];
    h[0] = words_of(p->h[0], 0);
    h[1] = words_of(p->h[1], 0);
    h[2] = words_of(p->h[2], 0);
    h[3] = words_of(p->h[3], 0);
    h[4] = words_of(p->h[4], 0);
    sums d[5];
#if PASS_PAIRS > 2
    if (pairs == PASS_PAIRS) {
        passes(d, h, m, n, &of_r, PASS_PAIRS);
    } else {
        passes(d, h, m, n, &of_r, 2);
    }
#else
    passes(d, h, m, n, &of_r, 2);
#endif

    // The two lanes' sums add up to the accumulator.
    uint64_t total[5];
    total[0] = sums_lane_total(d[0]);
    total[1] = sums_lane_total(d[1]);
    total[2] = sums_lane_total(d[2]);
    total[3] = sums_lane_total(d[3]);
    total[4] = sums_lane_total(d[4]);
    carry_scalar(p->h, total);
    ct_wipe(&of_r, sizeof of_r);
}

#endif // CH_POLY1305_VECTOR
