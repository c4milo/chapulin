#include "poly1305_vector.h"

// The whole file compiles only under CH_POLY1305_VECTOR (poly1305_vector.h).
#ifdef CH_POLY1305_VECTOR

#ifdef __ARM_NEON
#include <arm_neon.h>
#else
#include <emmintrin.h>
#endif

#include "ch_assert.h"
#include "poly1305_scalar.h"

// The 2^128 bit of a whole block, in its fifth word.
#define HIGH_BIT ((uint32_t)1 << 24)

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

// How multiply_add reads a multiplier. On x86-64 it reads each word
// through a volatile pointer, so a product loads its word from the struct
// where it uses it. x86-64 has 16 vector registers and a group's two
// multipliers are 18 vectors, so a compiler that loads them before the
// loop keeps some in stack slots it picks, which ct_wipe cannot name:
// Apple clang 21 left r^4 there, and bin/poly1305_equiv_test's residue
// check found it. Read this way, the powers stay in the one struct the
// call wipes. arm64 has 32 vector registers and holds both multipliers in
// them, so the same reads there remove nothing and cost 30 percent more
// instructions (docs/decisions.md 83).
#ifdef __ARM_NEON
typedef const multiplier multiplier_read;
#else
typedef const volatile multiplier multiplier_read;
#endif

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

// The sums for the group of four blocks at m. Lane 0 takes the group's
// first and third blocks and lane 1 its second and fourth, so each lane
// runs Horner's rule over every other block:
//
//   d = (h + the lane's first block) * first + (the lane's second block) * second
//
// Every array here is indexed by constants alone: gcc keeps an array that
// a loop indexes in memory, and reloads it on every group.
static inline void group_sums(sums d[5], const words h[5], const uint8_t *m, multiplier_read *first,
                              multiplier_read *second) {
    words first_blocks[5];
    words second_blocks[5];
    load_blocks(first_blocks, m);
    load_blocks(second_blocks, m + 32);
    first_blocks[0] = words_add(first_blocks[0], h[0]);
    first_blocks[1] = words_add(first_blocks[1], h[1]);
    first_blocks[2] = words_add(first_blocks[2], h[2]);
    first_blocks[3] = words_add(first_blocks[3], h[3]);
    first_blocks[4] = words_add(first_blocks[4], h[4]);
    d[0] = sums_zero();
    d[1] = sums_zero();
    d[2] = sums_zero();
    d[3] = sums_zero();
    d[4] = sums_zero();
    // The second blocks' products first: they do not wait on h.
    multiply_add(d, second_blocks, second);
    multiply_add(d, first_blocks, first);
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

// The five sums of each lane carried into words, in two rounds. The sums
// are below 2^59, and d4 below 2^56, since none of its products is by 5
// times a word, so its carry fits the 32 bits sums_add_carry_times_5
// takes. The first round leaves values below 2^33, and the second words
// below 2^26 + 2^10.
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

// What one call derives from r: r^2, r^3 and r^4, and the two
// multipliers built from them. r and a tag seen on the wire give the pad
// s, and r and s forge any message under that key, so the call wipes this
// struct through ct_wipe once, when it ends. One struct makes that one
// wipe. The registers and the spill slots the compiler picks stay out of
// its reach, as they do for every wipe written in C, which is why
// multiply_add reads the multipliers as multiplier_read says.
typedef struct {
    uint32_t r2[5];
    uint32_t r3[5];
    uint32_t r4[5];
    multiplier first;
    multiplier second;
} powers;

void poly1305_vector_blocks(poly1305 *p, const uint8_t *m, size_t n) {
    CH_ASSERT(n > 0 && n % POLY1305_VECTOR_GROUP == 0);
    // r^2, r^3 and r^4 beside r. Every group but the last multiplies both
    // lanes by r^4 and r^2, two steps of Horner's rule over every other
    // block. The last multiplies lane 0 by r^4 and r^2 and lane 1 by r^3
    // and r, the powers the last four blocks are owed.
    powers of_r;
    multiply_scalar(of_r.r2, p->r, p->r);
    multiply_scalar(of_r.r3, of_r.r2, p->r);
    multiply_scalar(of_r.r4, of_r.r2, of_r.r2);
    multiplier_set(&of_r.first, of_r.r4, of_r.r4);
    multiplier_set(&of_r.second, of_r.r2, of_r.r2);

    // Lane 0 starts from the accumulator and lane 1 from 0.
    words h[5];
    h[0] = words_of(p->h[0], 0);
    h[1] = words_of(p->h[1], 0);
    h[2] = words_of(p->h[2], 0);
    h[3] = words_of(p->h[3], 0);
    h[4] = words_of(p->h[4], 0);
    sums d[5];
    for (; n > POLY1305_VECTOR_GROUP; n -= POLY1305_VECTOR_GROUP) {
        group_sums(d, h, m, &of_r.first, &of_r.second);
        carry(h, d);
        m += POLY1305_VECTOR_GROUP;
    }
    multiplier_set(&of_r.first, of_r.r4, of_r.r3);
    multiplier_set(&of_r.second, of_r.r2, p->r);
    group_sums(d, h, m, &of_r.first, &of_r.second);

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
