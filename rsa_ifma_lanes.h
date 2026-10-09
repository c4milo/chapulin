// The lane operations rsa_ifma.c's kernel runs, each one AVX-512
// instruction on a 512-bit register of eight 64-bit lanes, lane 0 in bits
// 63..0. test/rsa_ifma_model_lanes.h defines the same names in portable C,
// written from Intel's pseudocode, and bin/rsa_ifma_equiv_test holds each
// function here to its model on a CPU with AVX-512 IFMA.
//
// Only rsa_ifma.c includes this file, between the attribute push that
// turns AVX-512F and AVX-512 IFMA on and its pop, so every function here
// carries that target and none outside the kernel does. Each operation
// works on all eight lanes at once and has no branch and no memory access
// that depends on a lane's value. The calls take a lane as a long long;
// the casts below keep its 64 bits, which is how gcc and clang define the
// conversion of a value above LLONG_MAX.
#ifndef CH_RSA_IFMA_LANES_H
#define CH_RSA_IFMA_LANES_H

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

#include <immintrin.h>
#include <stdint.h>

typedef __m512i rsa_ifma_lanes;
typedef __mmask8 rsa_ifma_lane_bits;

static inline rsa_ifma_lanes lanes_zero(void) {
    return _mm512_setzero_si512();
}

// value in every lane: VPBROADCASTQ.
static inline rsa_ifma_lanes lanes_broadcast(uint64_t value) {
    return _mm512_set1_epi64((long long)value);
}

// Lane j is words[j]: VMOVDQU64, which takes any address.
static inline rsa_ifma_lanes lanes_load(const uint64_t *words) {
    return _mm512_loadu_si512((const void *)words);
}

// words[j] is lane j: VMOVDQU64.
static inline void lanes_store(uint64_t *words, rsa_ifma_lanes lanes) {
    _mm512_storeu_si512((void *)words, lanes);
}

// Each lane of sum plus bits 51..0 of the product of bits 51..0 of the
// same lanes of x and y: VPMADD52LUQ.
static inline rsa_ifma_lanes lanes_multiply_add_low(rsa_ifma_lanes sum, rsa_ifma_lanes x,
                                                    rsa_ifma_lanes y) {
    return _mm512_madd52lo_epu64(sum, x, y);
}

// Each lane of sum plus bits 103..52 of the same product: VPMADD52HUQ.
static inline rsa_ifma_lanes lanes_multiply_add_high(rsa_ifma_lanes sum, rsa_ifma_lanes x,
                                                     rsa_ifma_lanes y) {
    return _mm512_madd52hi_epu64(sum, x, y);
}

// Lanes 1 to 7 of low in lanes 0 to 6, and lane 0 of high in lane 7:
// VALIGNQ with a count of 1.
static inline rsa_ifma_lanes lanes_down_one(rsa_ifma_lanes high, rsa_ifma_lanes low) {
    return _mm512_alignr_epi64(high, low, 1);
}

// Lane 7 of low in lane 0, and lanes 0 to 6 of high in lanes 1 to 7:
// VALIGNQ with a count of 7.
static inline rsa_ifma_lanes lanes_up_one(rsa_ifma_lanes high, rsa_ifma_lanes low) {
    return _mm512_alignr_epi64(high, low, 7);
}

// Lane 0: VMOVQ to a general register.
static inline uint64_t lanes_first(rsa_ifma_lanes lanes) {
    return (uint64_t)_mm_cvtsi128_si64(_mm512_castsi512_si128(lanes));
}

// lanes with lane 0 replaced by value: VPBROADCASTQ under a mask of bit 0
// alone, which keeps the other seven lanes.
static inline rsa_ifma_lanes lanes_replace_first(rsa_ifma_lanes lanes, uint64_t value) {
    return _mm512_mask_set1_epi64(lanes, (__mmask8)1, (long long)value);
}

// Each lane shifted right 52 bits: VPSRLQ.
static inline rsa_ifma_lanes lanes_shift_right_52(rsa_ifma_lanes lanes) {
    return _mm512_srli_epi64(lanes, 52);
}

static inline rsa_ifma_lanes lanes_and(rsa_ifma_lanes a, rsa_ifma_lanes b) {
    return _mm512_and_si512(a, b);
}

// Each lane of a plus the same lane of b, modulo 2^64: VPADDQ.
static inline rsa_ifma_lanes lanes_add(rsa_ifma_lanes a, rsa_ifma_lanes b) {
    return _mm512_add_epi64(a, b);
}

// Bit j is 1 where lane j of a is above lane j of b as unsigned numbers,
// in a mask register: _mm512_cmpgt_epu64_mask. The compiler picks the
// instruction. clang 23 emits VPCMPGTQ, a signed compare, which gives the
// unsigned answer for the lanes normalize_digits compares, each below
// 2^52 + 2^12 (docs/decisions.md 119).
static inline rsa_ifma_lane_bits lanes_above(rsa_ifma_lanes a, rsa_ifma_lanes b) {
    return _mm512_cmpgt_epu64_mask(a, b);
}

// Bit j is 1 where lane j of a equals lane j of b, in a mask register:
// _mm512_cmpeq_epu64_mask, which clang 23 emits as VPCMPEQQ.
static inline rsa_ifma_lane_bits lanes_equal(rsa_ifma_lanes a, rsa_ifma_lanes b) {
    return _mm512_cmpeq_epu64_mask(a, b);
}

// Lane j of a plus lane j of b where bit j of bits is 1, and lane j of
// source where it is 0: VPADDQ under a merging mask, which chooses each
// lane without a branch.
static inline rsa_ifma_lanes lanes_add_where(rsa_ifma_lanes source, rsa_ifma_lane_bits bits,
                                             rsa_ifma_lanes a, rsa_ifma_lanes b) {
    return _mm512_mask_add_epi64(source, bits, a, b);
}

#endif // CH_CPU_RUNTIME && __x86_64__

#endif
