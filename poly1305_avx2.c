#include "poly1305_avx2.h"

// The whole file compiles only under CH_POLY1305_AVX2 (poly1305_avx2.h):
// in an x86-64 host object's native copy.
#ifdef CH_POLY1305_AVX2

#include <immintrin.h>

#include "ch_assert.h"
#include "poly1305_scalar.h"

// Every function from here to the pop at the end of this file carries the
// target attribute that turns AVX2 on, and no function outside it does,
// as in chacha20_avx2.c: poly1305_scalar.h's steps above compile without
// it. The object is compiled with no instruction flag, so only these
// functions hold AVX2 instructions, and poly1305.c calls them only for an
// update that widemul_poly1305_update_cpu started for a session whose
// ch_cfg.cpu holds CH_CPU_AVX2.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx2"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx2")
#endif

// The 2^128 bit of a whole block, in its fifth limb.
#define HIGH_BIT ((uint32_t)1 << 24)

// The vector operations the group loop below is written in: those of
// poly1305_vector.c's SSE2 arm, on four lanes in place of two. VPMULUDQ
// reads the low 32 bits of each 64-bit lane, so a limbs vector holds one
// limb there in each of four lanes, with 0 in each lane's high 32 bits,
// and a sums vector holds one 64-bit sum of products in each of the same
// four lanes. Every operation acts on all four lanes at once and has no
// branch and no memory access that depends on a lane's value. The AVX2
// calls take a lane's word as an int; the casts below keep its 32 bits,
// which is how gcc and clang define the conversion of a value above
// INT_MAX.
typedef __m256i limbs;
typedef __m256i sums;

static inline limbs limbs_of(uint32_t lane0, uint32_t lane1, uint32_t lane2, uint32_t lane3) {
    return _mm256_set_epi32(0, (int)lane3, 0, (int)lane2, 0, (int)lane1, 0, (int)lane0);
}

// limb in every lane: one broadcast.
static inline limbs limbs_broadcast(uint32_t limb) {
    return _mm256_set1_epi64x((long long)limb);
}

static inline limbs limbs_add(limbs a, limbs b) {
    return _mm256_add_epi64(a, b);
}

static inline sums sums_zero(void) {
    return _mm256_setzero_si256();
}

// sum + a * b in each lane, the product widened to 64 bits: VPMULUDQ.
static inline sums sums_multiply_add(sums sum, limbs a, limbs b) {
    return _mm256_add_epi64(sum, _mm256_mul_epu32(a, b));
}

// sum + (from >> 26) in each lane.
static inline sums sums_add_carry(sums sum, sums from) {
    return _mm256_add_epi64(sum, _mm256_srli_epi64(from, 26));
}

// sum + (from >> 26) * 5 in each lane, as the carry plus 4 times it.
static inline sums sums_add_carry_times_5(sums sum, sums from) {
    sums carry = _mm256_srli_epi64(from, 26);
    return _mm256_add_epi64(_mm256_add_epi64(sum, carry), _mm256_slli_epi64(carry, 2));
}

static inline sums sums_low_limb(sums a) {
    return _mm256_and_si256(a, _mm256_set1_epi64x(LIMB_MASK));
}

// A sum below 2^32 is already a limbs vector: its high 32 bits are 0.
static inline limbs sums_narrow(sums a) {
    return a;
}

// The four lanes' total: the high 128 bits added to the low 128, then the
// high lane of that sum to its low one, and the low 64 bits stored.
static inline uint64_t sums_lane_total(sums a) {
    __m128i halves = _mm_add_epi64(_mm256_castsi256_si128(a), _mm256_extracti128_si256(a, 1));
    uint64_t total = 0;
    _mm_storel_epi64((__m128i *)(void *)&total,
                     _mm_add_epi64(halves, _mm_unpackhi_epi64(halves, halves)));
    return total;
}

// The 16 bytes at m.
static inline __m128i load_16(const uint8_t *m) {
    return _mm_loadu_si128((const __m128i *)(const void *)m);
}

// The five limbs of the four blocks at m, block j in lane j, each with
// its 2^128 bit. One vector takes blocks 0 and 2 and another blocks 1 and
// 3, so unpacking their low 64-bit halves, and then their high ones, puts
// each block's eight bytes in its own lane: the unpack works within each
// 128-bit half. A 64-bit lane holds eight bytes of a block, little-endian
// as poly1305_vector.h requires.
static inline void load_blocks(limbs out[5], const uint8_t *m) {
    __m256i even = _mm256_inserti128_si256(_mm256_castsi128_si256(load_16(m)), load_16(m + 32), 1);
    __m256i odd =
        _mm256_inserti128_si256(_mm256_castsi128_si256(load_16(m + 16)), load_16(m + 48), 1);
    __m256i low = _mm256_unpacklo_epi64(even, odd);
    __m256i high = _mm256_unpackhi_epi64(even, odd);
    __m256i mask = _mm256_set1_epi64x(LIMB_MASK);
    out[0] = _mm256_and_si256(low, mask);
    out[1] = _mm256_and_si256(_mm256_srli_epi64(low, 26), mask);
    out[2] = _mm256_and_si256(
        _mm256_or_si256(_mm256_srli_epi64(low, 52), _mm256_slli_epi64(high, 12)), mask);
    out[3] = _mm256_and_si256(_mm256_srli_epi64(high, 14), mask);
    out[4] = _mm256_or_si256(_mm256_srli_epi64(high, 40), _mm256_set1_epi64x(HIGH_BIT));
}

// A power of r in each lane, as poly1305.c's loop holds r: the five limbs,
// and 5 times each of the four whose products pass 2^130.
typedef struct {
    limbs r0, r1, r2, r3, r4;
    limbs s1, s2, s3, s4;
} multiplier;

// multiply_add reads each limb of a multiplier through a volatile
// pointer, as poly1305_vector.c's SSE2 arm does, and for its reason: AVX2
// has 16 vector registers and a group's two multipliers are 18 vectors,
// so a compiler that loads them before the loop keeps some in stack slots
// it picks, which ct_wipe cannot name. Read this way, a product loads its
// limb from the struct where it uses it, and the powers stay in the one
// struct the call wipes.
typedef const volatile multiplier multiplier_read;

// Limb i of each of the four powers, power j in lane j, times factor: 1
// for the limb itself and 5 for the limb a product past 2^130 takes. Each
// limb is at most 2^26, so 5 times it fits in 32 bits.
static limbs limb_lanes(const uint32_t *const power[4], size_t limb, uint32_t factor) {
    return limbs_of(power[0][limb] * factor, power[1][limb] * factor, power[2][limb] * factor,
                    power[3][limb] * factor);
}

// power in every lane, for every group but the last.
static void multiplier_broadcast(multiplier *by, const uint32_t power[5]) {
    by->r0 = limbs_broadcast(power[0]);
    by->r1 = limbs_broadcast(power[1]);
    by->r2 = limbs_broadcast(power[2]);
    by->r3 = limbs_broadcast(power[3]);
    by->r4 = limbs_broadcast(power[4]);
    by->s1 = limbs_broadcast(power[1] * 5);
    by->s2 = limbs_broadcast(power[2] * 5);
    by->s3 = limbs_broadcast(power[3] * 5);
    by->s4 = limbs_broadcast(power[4] * 5);
}

// power[j] in lane j, for the last group.
static void multiplier_set(multiplier *by, const uint32_t *const power[4]) {
    by->r0 = limb_lanes(power, 0, 1);
    by->r1 = limb_lanes(power, 1, 1);
    by->r2 = limb_lanes(power, 2, 1);
    by->r3 = limb_lanes(power, 3, 1);
    by->r4 = limb_lanes(power, 4, 1);
    by->s1 = limb_lanes(power, 1, 5);
    by->s2 = limb_lanes(power, 2, 5);
    by->s3 = limb_lanes(power, 3, 5);
    by->s4 = limb_lanes(power, 4, 5);
}

// d += a * by in each lane: poly1305.c's five sums of five products, in
// the order poly1305_vector.c's multiply_add takes them and for its
// reason: a2, a3 and a4 before a0 and a1, which carry below finishes
// last. It and group_sums carry the attribute for the reason
// poly1305_vector.c's multiply_add gives.
static inline __attribute__((always_inline)) void multiply_add(sums d[5], const limbs a[5],
                                                               multiplier_read *by) {
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

// The sums for the group of eight blocks at m. Lane j takes the group's
// block j and block j + 4, so each lane runs Horner's rule over every
// fourth block:
//
//   d = (h + the lane's first block) * first + (the lane's second block) * second
//
// Every array here is indexed by constants alone, as in
// poly1305_vector.c's group_sums.
static inline __attribute__((always_inline)) void group_sums(sums d[5], const limbs h[5],
                                                             const uint8_t *m,
                                                             multiplier_read *first,
                                                             multiplier_read *second) {
    limbs first_blocks[5];
    limbs second_blocks[5];
    load_blocks(first_blocks, m);
    load_blocks(second_blocks, m + 64);
    first_blocks[0] = limbs_add(first_blocks[0], h[0]);
    first_blocks[1] = limbs_add(first_blocks[1], h[1]);
    first_blocks[2] = limbs_add(first_blocks[2], h[2]);
    first_blocks[3] = limbs_add(first_blocks[3], h[3]);
    first_blocks[4] = limbs_add(first_blocks[4], h[4]);
    d[0] = sums_zero();
    d[1] = sums_zero();
    d[2] = sums_zero();
    d[3] = sums_zero();
    d[4] = sums_zero();
    // The second blocks' products first: they do not wait on h.
    multiply_add(d, second_blocks, second);
    multiply_add(d, first_blocks, first);
}

// One round of carries, as poly1305_vector.c's carry_round: each value's
// low 26 bits plus the carry out of the value below it, and for value 0 5
// times the carry out of value 4.
static inline void carry_round(sums out[5], const sums in[5]) {
    out[0] = sums_add_carry_times_5(sums_low_limb(in[0]), in[4]);
    out[1] = sums_add_carry(sums_low_limb(in[1]), in[0]);
    out[2] = sums_add_carry(sums_low_limb(in[2]), in[1]);
    out[3] = sums_add_carry(sums_low_limb(in[3]), in[2]);
    out[4] = sums_add_carry(sums_low_limb(in[4]), in[3]);
}

// The five sums of each lane carried into limbs, in two rounds. A lane's
// sums are below 2^58, and d4 below 2^56, since none of its products is
// by 5 times a limb. The first round leaves values below 2^33, and the
// second limbs below 2^26 + 2^10.
static inline void carry(limbs h[5], const sums d[5]) {
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

// What one call derives from r: r^2 to r^8, and the two multipliers built
// from them, in one struct that the call wipes once, when it ends, for
// the reason poly1305_vector.c's powers struct gives: r and a tag seen on
// the wire give the pad s, and r and s forge any message under that key.
typedef struct {
    uint32_t r2[5];
    uint32_t r3[5];
    uint32_t r4[5];
    uint32_t r5[5];
    uint32_t r6[5];
    uint32_t r7[5];
    uint32_t r8[5];
    multiplier first;
    multiplier second;
} powers;

void poly1305_avx2_blocks(poly1305 *p, const uint8_t *m, size_t n) {
    CH_ASSERT(n > 0 && n % POLY1305_AVX2_GROUP == 0);
    // r^2 to r^8 beside r. Every group but the last multiplies each lane
    // by r^8 and r^4, two steps of Horner's rule over every fourth block.
    // The last multiplies lane j by r^(8 - j) and r^(4 - j), the powers the
    // last eight blocks are owed.
    powers of_r;
    multiply_scalar(of_r.r2, p->r, p->r);
    multiply_scalar(of_r.r3, of_r.r2, p->r);
    multiply_scalar(of_r.r4, of_r.r2, of_r.r2);
    multiply_scalar(of_r.r5, of_r.r4, p->r);
    multiply_scalar(of_r.r6, of_r.r4, of_r.r2);
    multiply_scalar(of_r.r7, of_r.r4, of_r.r3);
    multiply_scalar(of_r.r8, of_r.r4, of_r.r4);
    multiplier_broadcast(&of_r.first, of_r.r8);
    multiplier_broadcast(&of_r.second, of_r.r4);

    // Lane 0 starts from the accumulator and lanes 1 to 3 from 0.
    limbs h[5];
    h[0] = limbs_of(p->h[0], 0, 0, 0);
    h[1] = limbs_of(p->h[1], 0, 0, 0);
    h[2] = limbs_of(p->h[2], 0, 0, 0);
    h[3] = limbs_of(p->h[3], 0, 0, 0);
    h[4] = limbs_of(p->h[4], 0, 0, 0);
    sums d[5];
    for (; n > POLY1305_AVX2_GROUP; n -= POLY1305_AVX2_GROUP) {
        group_sums(d, h, m, &of_r.first, &of_r.second);
        carry(h, d);
        m += POLY1305_AVX2_GROUP;
    }
    const uint32_t *const last_first[4] = {of_r.r8, of_r.r7, of_r.r6, of_r.r5};
    const uint32_t *const last_second[4] = {of_r.r4, of_r.r3, of_r.r2, p->r};
    multiplier_set(&of_r.first, last_first);
    multiplier_set(&of_r.second, last_second);
    group_sums(d, h, m, &of_r.first, &of_r.second);

    // The four lanes' sums add up to the accumulator. Each lane's sums are
    // below 2^58, so the totals are below 2^60, which carry_scalar takes.
    uint64_t total[5];
    total[0] = sums_lane_total(d[0]);
    total[1] = sums_lane_total(d[1]);
    total[2] = sums_lane_total(d[2]);
    total[3] = sums_lane_total(d[3]);
    total[4] = sums_lane_total(d[4]);
    // carry_scalar compiles without AVX, and gcc 13 calls it with the upper
    // halves of the 256-bit registers still written. On an AMD EPYC 7763
    // that call and the wipe after it took about 260 more TSC cycles than
    // with the halves cleared, so the kernel clears them first
    // (docs/decisions.md 110).
    _mm256_zeroupper();
    carry_scalar(p->h, total);
    ct_wipe(&of_r, sizeof of_r);
}

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif

#endif // CH_POLY1305_AVX2
