// The lane operations a host object's ML-KEM arithmetic is written in
// (mlkem_vector.c), one set per instruction set: eight 16-bit lanes in one
// NEON register on arm64, or in one SSE2 register on x86-64. Each
// operation computes what mlkem_poly.c computes for each lane's
// coefficient, to the same int16 value, and the comment above each says
// why. mlkem_vector.c alone includes this header.
#ifndef CH_MLKEM_LANES_H
#define CH_MLKEM_LANES_H

#include <stdint.h>

#include "cpu_cfg.h"
#include "mlkem.h"

// Everything below exists only in a host object (mlkem_vector.h).
#ifdef CH_CPU_RUNTIME

#ifdef __ARM_NEON
#include <arm_neon.h>
#else
#include <emmintrin.h>
#endif

// Each operation works on all eight lanes at once and has no branch and no
// memory access that depends on a lane's value.

#ifdef __ARM_NEON

// Eight 16-bit lanes in one NEON register.
typedef int16x8_t lanes;

static inline lanes lanes_load(const int16_t *p) {
    return vld1q_s16(p);
}

static inline void lanes_store(int16_t *p, lanes x) {
    vst1q_s16(p, x);
}

static inline lanes lanes_broadcast(int16_t x) {
    return vdupq_n_s16(x);
}

// Each lane's sum and difference modulo 2^16, as mlkem_poly.c's (int16_t)
// casts give them.
static inline lanes lanes_add(lanes a, lanes b) {
    return vaddq_s16(a, b);
}

static inline lanes lanes_sub(lanes a, lanes b) {
    return vsubq_s16(a, b);
}

// The low 16 bits of each lane's product.
static inline lanes lanes_mul_low(lanes a, lanes b) {
    return vmulq_s16(a, b);
}

// mlk_fqmul(a, z) in each lane, with z_qinv the low 16 bits of z * -3327.
// mlkem_poly.c computes (a*z - t*q) >> 16, where t is the low 16 bits of
// a*z*-3327, so t is also the low 16 bits of a*z_qinv, and a*z - t*q is a
// multiple of 2^16 that fits in 32 bits for every int16 a.
//
// SQDMULH gives the high 16 bits of the doubled product, floor(2xy /
// 2^16). The doubled products 2az and 2tq agree in their low 16 bits,
// because az and tq do, so high - low is exactly (2az - 2tq) / 2^16, and it
// is even, because az - tq is a multiple of 2^16. SHSUB subtracts and
// halves in a wider intermediate, so each lane holds (az - tq) / 2^16, the
// value of mlkem_poly.c's shift. SQDMULH saturates only when both of its
// operands are -32768: z is a twiddle factor or 1441, and q is 3329.
static inline lanes lanes_fqmul(lanes a, lanes z, lanes z_qinv) {
    lanes t = vmulq_s16(a, z_qinv);
    lanes high = vqdmulhq_s16(a, z);
    lanes low = vqdmulhq_n_s16(t, MLKEM_Q);
    return vhsubq_s16(high, low);
}

// mlk_barrett_reduce(a) in each lane: a - t*q, where t = floor((20159*a +
// 2^25) / 2^26). SQDMULH by 20159 gives floor(20159*a / 2^15), at most
// 20159 in size and with no saturation, so adding 2^10 stays in 16 bits,
// and the arithmetic shift by 11 gives t = floor((floor(20159*a / 2^15) +
// 2^10) / 2^11) = floor((20159*a + 2^25) / 2^26). MLS subtracts t*q modulo
// 2^16, and a - t*q fits in 16 bits, so the lane holds it exactly. The add
// and the shift are two instructions where SRSHR would be one, because
// Arm's data-independent-timing list names SRSHR in its scalar form
// alone.
static inline lanes lanes_barrett_reduce(lanes a) {
    lanes x = vqdmulhq_n_s16(a, 20159);
    lanes t = vshrq_n_s16(vaddq_s16(x, vdupq_n_s16(1024)), 11);
    return vmlsq_n_s16(a, t, MLKEM_Q);
}

// For two vectors a and b, which hold 16 consecutive coefficients: lo gets
// the first four of each eight, (a0..a3, b0..b3), and hi the last four,
// (a4..a7, b4..b7), so lane i of lo and lane i of hi are a butterfly pair
// of the layer of span 4.
static inline void lanes_split_quads(lanes a, lanes b, lanes *lo, lanes *hi) {
    int64x2_t a64 = vreinterpretq_s64_s16(a);
    int64x2_t b64 = vreinterpretq_s64_s16(b);
    *lo = vreinterpretq_s16_s64(vzip1q_s64(a64, b64));
    *hi = vreinterpretq_s16_s64(vzip2q_s64(a64, b64));
}

// The same for the layer of span 2: lo gets the first two of each four,
// (a0, a1, a4, a5, b0, b1, b4, b5), and hi the last two, (a2, a3, a6, a7,
// b2, b3, b6, b7). Each 32-bit lane holds two neighbouring coefficients.
static inline void lanes_split_pairs(lanes a, lanes b, lanes *lo, lanes *hi) {
    int32x4_t a32 = vreinterpretq_s32_s16(a);
    int32x4_t b32 = vreinterpretq_s32_s16(b);
    *lo = vreinterpretq_s16_s32(vuzp1q_s32(a32, b32));
    *hi = vreinterpretq_s16_s32(vuzp2q_s32(a32, b32));
}

// The inverse of lanes_split_pairs.
static inline void lanes_join_pairs(lanes lo, lanes hi, lanes *a, lanes *b) {
    int32x4_t lo32 = vreinterpretq_s32_s16(lo);
    int32x4_t hi32 = vreinterpretq_s32_s16(hi);
    *a = vreinterpretq_s16_s32(vzip1q_s32(lo32, hi32));
    *b = vreinterpretq_s16_s32(vzip2q_s32(lo32, hi32));
}

// (z[0], z[0], z[0], z[0], z[1], z[1], z[1], z[1]).
static inline lanes lanes_quads(const int16_t z[2]) {
    return vcombine_s16(vld1_dup_s16(&z[0]), vld1_dup_s16(&z[1]));
}

// (z[1], z[1], z[1], z[1], z[0], z[0], z[0], z[0]).
static inline lanes lanes_quads_reversed(const int16_t z[2]) {
    return vcombine_s16(vld1_dup_s16(&z[1]), vld1_dup_s16(&z[0]));
}

// (z[0], z[0], z[1], z[1], z[2], z[2], z[3], z[3]).
static inline lanes lanes_pairs(const int16_t z[4]) {
    int16x4x2_t twice = vzip_s16(vld1_s16(z), vld1_s16(z));
    return vcombine_s16(twice.val[0], twice.val[1]);
}

// (z[3], z[3], z[2], z[2], z[1], z[1], z[0], z[0]).
static inline lanes lanes_pairs_reversed(const int16_t z[4]) {
    int16x4_t reversed = vrev64_s16(vld1_s16(z));
    int16x4x2_t twice = vzip_s16(reversed, reversed);
    return vcombine_s16(twice.val[0], twice.val[1]);
}

// mlk_fqmul(x, y) in each lane for two vectors of coefficients, with
// y_qinv the low 16 bits of y * -3327. lanes_fqmul's SQDMULH saturates
// where both operands are -32768, which a twiddle factor never is and a
// coefficient can be, so this form is exact for every pair of int16
// values instead: SMULL forms each product x*y and t*q in 32 bits, their
// difference is a multiple of 2^16 and fits in 32 bits, and UZP2 takes
// the high half of each, the quotient by 2^16.
static inline lanes lanes_fqmul_wide(lanes x, lanes y, lanes y_qinv) {
    lanes t = vmulq_s16(x, y_qinv);
    int32x4_t low = vsubq_s32(vmull_s16(vget_low_s16(x), vget_low_s16(y)),
                              vmull_n_s16(vget_low_s16(t), MLKEM_Q));
    int32x4_t high = vsubq_s32(vmull_high_s16(x, y), vmull_high_n_s16(t, MLKEM_Q));
    return vuzp2q_s16(vreinterpretq_s16_s32(low), vreinterpretq_s16_s32(high));
}

// For two vectors a and b, which hold 16 consecutive coefficients: even
// gets the coefficients at even positions, (a0, a2, a4, a6, b0, b2, b4,
// b6), and odd the ones after them, so lane i of the two is one pair of
// mlk_poly_basemul.
static inline void lanes_split_even_odd(lanes a, lanes b, lanes *even, lanes *odd) {
    *even = vuzp1q_s16(a, b);
    *odd = vuzp2q_s16(a, b);
}

// The inverse of lanes_split_even_odd.
static inline void lanes_join_even_odd(lanes even, lanes odd, lanes *a, lanes *b) {
    *a = vzip1q_s16(even, odd);
    *b = vzip2q_s16(even, odd);
}

// (1, -1, 1, -1, 1, -1, 1, -1).
static inline lanes lanes_alternate_signs(void) {
    static const int16_t signs[8] = {1, -1, 1, -1, 1, -1, 1, -1};
    return vld1q_s16(signs);
}

#else

// Eight 16-bit lanes in one SSE2 register.
typedef __m128i lanes;

static inline lanes lanes_load(const int16_t *p) {
    return _mm_loadu_si128((const __m128i *)(const void *)p);
}

static inline void lanes_store(int16_t *p, lanes x) {
    _mm_storeu_si128((__m128i *)(void *)p, x);
}

static inline lanes lanes_broadcast(int16_t x) {
    return _mm_set1_epi16(x);
}

// Each lane's sum and difference modulo 2^16, as mlkem_poly.c's (int16_t)
// casts give them.
static inline lanes lanes_add(lanes a, lanes b) {
    return _mm_add_epi16(a, b);
}

static inline lanes lanes_sub(lanes a, lanes b) {
    return _mm_sub_epi16(a, b);
}

// The low 16 bits of each lane's product.
static inline lanes lanes_mul_low(lanes a, lanes b) {
    return _mm_mullo_epi16(a, b);
}

// mlk_fqmul(a, z) in each lane, with z_qinv the low 16 bits of z * -3327:
// (a*z - t*q) / 2^16, where t is the low 16 bits of a*z_qinv (see the NEON
// version above). PMULHW gives the high 16 bits of the product,
// floor(xy / 2^16). az and tq agree in their low 16 bits, so high - low is
// exactly (az - tq) / 2^16, and the difference fits in 16 bits.
static inline lanes lanes_fqmul(lanes a, lanes z, lanes z_qinv) {
    lanes t = _mm_mullo_epi16(a, z_qinv);
    lanes high = _mm_mulhi_epi16(a, z);
    lanes low = _mm_mulhi_epi16(t, _mm_set1_epi16(MLKEM_Q));
    return _mm_sub_epi16(high, low);
}

// mlk_barrett_reduce(a) in each lane: a - t*q, where t = floor((20159*a +
// 2^25) / 2^26). PMULHW by 20159 gives floor(20159*a / 2^16), at most 10080
// in size, so adding 2^9 stays in 16 bits, and the arithmetic shift by 10
// gives t = floor((floor(20159*a / 2^16) + 2^9) / 2^10) =
// floor((20159*a + 2^25) / 2^26). The subtraction is modulo 2^16, and
// a - t*q fits in 16 bits, so the lane holds it exactly.
static inline lanes lanes_barrett_reduce(lanes a) {
    lanes x = _mm_mulhi_epi16(a, _mm_set1_epi16(20159));
    lanes t = _mm_srai_epi16(_mm_add_epi16(x, _mm_set1_epi16(512)), 10);
    return _mm_sub_epi16(a, _mm_mullo_epi16(t, _mm_set1_epi16(MLKEM_Q)));
}

// For two vectors a and b, which hold 16 consecutive coefficients: lo gets
// the first four of each eight, (a0..a3, b0..b3), and hi the last four,
// (a4..a7, b4..b7), so lane i of lo and lane i of hi are a butterfly pair
// of the layer of span 4.
static inline void lanes_split_quads(lanes a, lanes b, lanes *lo, lanes *hi) {
    *lo = _mm_unpacklo_epi64(a, b);
    *hi = _mm_unpackhi_epi64(a, b);
}

// The same for the layer of span 2: lo gets the first two of each four,
// (a0, a1, a4, a5, b0, b1, b4, b5), and hi the last two, (a2, a3, a6, a7,
// b2, b3, b6, b7). Each 32-bit lane holds two neighbouring coefficients:
// the shuffles put a vector's 32-bit lanes in the order 0, 2, 1, 3, which
// the immediate 0xd8 names two bits a lane, and the unpacks take the first
// halves and the second halves of the two.
static inline void lanes_split_pairs(lanes a, lanes b, lanes *lo, lanes *hi) {
    lanes a_even_first = _mm_shuffle_epi32(a, 0xd8);
    lanes b_even_first = _mm_shuffle_epi32(b, 0xd8);
    *lo = _mm_unpacklo_epi64(a_even_first, b_even_first);
    *hi = _mm_unpackhi_epi64(a_even_first, b_even_first);
}

// The inverse of lanes_split_pairs.
static inline void lanes_join_pairs(lanes lo, lanes hi, lanes *a, lanes *b) {
    *a = _mm_unpacklo_epi32(lo, hi);
    *b = _mm_unpackhi_epi32(lo, hi);
}

// (z[0], z[0], z[0], z[0], z[1], z[1], z[1], z[1]).
static inline lanes lanes_quads(const int16_t z[2]) {
    return _mm_unpacklo_epi64(_mm_set1_epi16(z[0]), _mm_set1_epi16(z[1]));
}

// (z[1], z[1], z[1], z[1], z[0], z[0], z[0], z[0]).
static inline lanes lanes_quads_reversed(const int16_t z[2]) {
    return _mm_unpacklo_epi64(_mm_set1_epi16(z[1]), _mm_set1_epi16(z[0]));
}

// (z[0], z[0], z[1], z[1], z[2], z[2], z[3], z[3]).
static inline lanes lanes_pairs(const int16_t z[4]) {
    lanes four = _mm_loadl_epi64((const __m128i *)(const void *)z);
    return _mm_unpacklo_epi16(four, four);
}

// (z[3], z[3], z[2], z[2], z[1], z[1], z[0], z[0]). The immediate 0x1b
// names the low four 16-bit lanes in the order 3, 2, 1, 0.
static inline lanes lanes_pairs_reversed(const int16_t z[4]) {
    lanes four = _mm_loadl_epi64((const __m128i *)(const void *)z);
    lanes reversed = _mm_shufflelo_epi16(four, 0x1b);
    return _mm_unpacklo_epi16(reversed, reversed);
}

// mlk_fqmul(x, y) in each lane for two vectors of coefficients, with
// y_qinv the low 16 bits of y * -3327. PMULHW forms the high half of
// every product of two int16 values exactly, so this is lanes_fqmul.
static inline lanes lanes_fqmul_wide(lanes x, lanes y, lanes y_qinv) {
    return lanes_fqmul(x, y, y_qinv);
}

// For two vectors a and b, which hold 16 consecutive coefficients: even
// gets the coefficients at even positions, (a0, a2, a4, a6, b0, b2, b4,
// b6), and odd the ones after them, so lane i of the two is one pair of
// mlk_poly_basemul. The three shuffles of each vector, under the
// immediate 0xd8, which names the order 0, 2, 1, 3, put its four even
// coefficients in its low 64 bits and its four odd ones in its high 64,
// and the unpacks take the low halves and the high halves of the two.
static inline void lanes_split_even_odd(lanes a, lanes b, lanes *even, lanes *odd) {
    lanes a_split =
        _mm_shuffle_epi32(_mm_shufflehi_epi16(_mm_shufflelo_epi16(a, 0xd8), 0xd8), 0xd8);
    lanes b_split =
        _mm_shuffle_epi32(_mm_shufflehi_epi16(_mm_shufflelo_epi16(b, 0xd8), 0xd8), 0xd8);
    *even = _mm_unpacklo_epi64(a_split, b_split);
    *odd = _mm_unpackhi_epi64(a_split, b_split);
}

// The inverse of lanes_split_even_odd.
static inline void lanes_join_even_odd(lanes even, lanes odd, lanes *a, lanes *b) {
    *a = _mm_unpacklo_epi16(even, odd);
    *b = _mm_unpackhi_epi16(even, odd);
}

// (1, -1, 1, -1, 1, -1, 1, -1).
static inline lanes lanes_alternate_signs(void) {
    return _mm_setr_epi16(1, -1, 1, -1, 1, -1, 1, -1);
}

#endif

// lanes_split_quads applied to its own output gives back its input, so it
// is its own inverse.
static inline void lanes_join_quads(lanes lo, lanes hi, lanes *a, lanes *b) {
    lanes_split_quads(lo, hi, a, b);
}

#endif // CH_CPU_RUNTIME

#endif
