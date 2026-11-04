// The lane operations rsa_avx2.c's kernel runs, each one AVX2 instruction
// on a 256-bit register of four 64-bit lanes, lane 0 in bits 63..0.
// test/rsa_avx2_model_lanes.h defines the same names in portable C,
// written from Intel's pseudocode, and bin/rsa_avx2_equiv_test holds each
// function here to its model on a CPU with AVX2.
//
// Only rsa_avx2.c includes this file, between the attribute push that
// turns AVX2 on and its pop, so every function here carries that target
// and none outside the kernel does. Each operation works on all four lanes
// at once and has no branch and no memory access that depends on a lane's
// value. _mm256_set1_epi64x takes a lane as a long long; the cast below
// keeps its 64 bits, which is how gcc and clang define the conversion of a
// value above LLONG_MAX.
#ifndef CH_RSA_AVX2_LANES_H
#define CH_RSA_AVX2_LANES_H

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

#include <immintrin.h>
#include <stdint.h>

typedef __m256i rsa_avx2_lanes;

static inline rsa_avx2_lanes lanes_zero(void) {
    return _mm256_setzero_si256();
}

// value in every lane: VPBROADCASTQ.
static inline rsa_avx2_lanes lanes_broadcast(uint64_t value) {
    return _mm256_set1_epi64x((long long)value);
}

// Lane j is words[j]: VMOVDQU, which takes any address.
static inline rsa_avx2_lanes lanes_load(const uint64_t *words) {
    return _mm256_loadu_si256((const __m256i *)(const void *)words);
}

// words[j] is lane j: VMOVDQU.
static inline void lanes_store(uint64_t *words, rsa_avx2_lanes lanes) {
    _mm256_storeu_si256((__m256i *)(void *)words, lanes);
}

// Each lane the product of bits 31..0 of the same lanes of x and y, all 64
// bits of it: VPMULUDQ.
static inline rsa_avx2_lanes lanes_multiply(rsa_avx2_lanes x, rsa_avx2_lanes y) {
    return _mm256_mul_epu32(x, y);
}

// Each lane of a plus the same lane of b, modulo 2^64: VPADDQ.
static inline rsa_avx2_lanes lanes_add(rsa_avx2_lanes a, rsa_avx2_lanes b) {
    return _mm256_add_epi64(a, b);
}

// Lane 0 of low and lanes 1 to 3 of high: VPBLENDD, which picks the two
// 32-bit halves of lane 0 from low.
static inline rsa_avx2_lanes lanes_first_from(rsa_avx2_lanes high, rsa_avx2_lanes low) {
    return _mm256_blend_epi32(high, low, 0x03);
}

// Zero in lanes 0 and 1, lane 2 of low and lane 3 of high: two VPBLENDDs,
// the first of low over a register of zeros and the second of high over
// that.
static inline rsa_avx2_lanes lanes_upper_two(rsa_avx2_lanes high, rsa_avx2_lanes low) {
    return _mm256_blend_epi32(_mm256_blend_epi32(_mm256_setzero_si256(), low, 0x30), high, 0xc0);
}

#endif // CH_CPU_RUNTIME && __x86_64__

#endif
