// The lane operations poly1305_ifma.c's kernel runs, each one AVX-512
// instruction on a 512-bit register of eight 64-bit lanes, lane 0 in bits
// 63..0, but for lanes_total, the eight lanes' sum, which the compiler
// writes as a few adds and lane moves, and lanes_wipe_registers, the call
// that zeros every vector register. test/poly1305_ifma_model_lanes.h
// defines the same names in portable C, written from Intel's pseudocode,
// and bin/poly1305_equiv_test holds the kernel on these to poly1305.c's
// loop on a CPU with AVX-512 IFMA.
//
// Only poly1305_ifma.c includes this file, between the attribute push that
// turns AVX-512F and AVX-512 IFMA on and its pop, so every function here
// carries that target and none outside the kernel does. Each operation
// works on all eight lanes at once and has no branch and no memory access
// that depends on a lane's value. The calls take a lane as a long long;
// the casts below keep its 64 bits, which is how gcc and clang define the
// conversion of a value above LLONG_MAX.
#ifndef CH_POLY1305_IFMA_LANES_H
#define CH_POLY1305_IFMA_LANES_H

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

#include <immintrin.h>
#include <stdint.h>

typedef __m512i poly1305_ifma_lanes;
// A mask register of eight bits, bit j for lane j.
typedef __mmask8 poly1305_ifma_lane_bits;

static inline poly1305_ifma_lanes lanes_zero(void) {
    return _mm512_setzero_si512();
}

// value in every lane: VPBROADCASTQ.
static inline poly1305_ifma_lanes lanes_broadcast(uint64_t value) {
    return _mm512_set1_epi64((long long)value);
}

// value in lane 0 and 0 in the other seven: VPBROADCASTQ under a zeroing
// mask of bit 0 alone.
static inline poly1305_ifma_lanes lanes_first_only(uint64_t value) {
    return _mm512_maskz_set1_epi64((__mmask8)1, (long long)value);
}

// Lane 0 of a in every lane: VPBROADCASTQ from a register.
static inline poly1305_ifma_lanes lanes_broadcast_first(poly1305_ifma_lanes a) {
    return _mm512_broadcastq_epi64(_mm512_castsi512_si128(a));
}

// The 64 bytes at bytes, lane j from bytes 8j to 8j + 7, little-endian:
// VMOVDQU64, which takes any address.
static inline poly1305_ifma_lanes lanes_load_bytes(const uint8_t *bytes) {
    return _mm512_loadu_si512((const void *)bytes);
}

// Lane 2i of a in lane 2i and lane 2i of b in lane 2i + 1, for i from 0 to
// 3: VPUNPCKLQDQ.
static inline poly1305_ifma_lanes lanes_interleave_low(poly1305_ifma_lanes a,
                                                       poly1305_ifma_lanes b) {
    return _mm512_unpacklo_epi64(a, b);
}

// Lane 2i + 1 of a in lane 2i and lane 2i + 1 of b in lane 2i + 1:
// VPUNPCKHQDQ.
static inline poly1305_ifma_lanes lanes_interleave_high(poly1305_ifma_lanes a,
                                                        poly1305_ifma_lanes b) {
    return _mm512_unpackhi_epi64(a, b);
}

// Each lane of a plus the same lane of b, modulo 2^64: VPADDQ.
static inline poly1305_ifma_lanes lanes_add(poly1305_ifma_lanes a, poly1305_ifma_lanes b) {
    return _mm512_add_epi64(a, b);
}

static inline poly1305_ifma_lanes lanes_and(poly1305_ifma_lanes a, poly1305_ifma_lanes b) {
    return _mm512_and_si512(a, b);
}

static inline poly1305_ifma_lanes lanes_or(poly1305_ifma_lanes a, poly1305_ifma_lanes b) {
    return _mm512_or_si512(a, b);
}

// Each lane shifted left or right by count bits, count below 64: VPSLLQ
// and VPSRLQ. Every call passes a constant, which the instruction takes as
// an immediate.
static inline poly1305_ifma_lanes lanes_shift_left(poly1305_ifma_lanes a, unsigned count) {
    return _mm512_slli_epi64(a, count);
}

static inline poly1305_ifma_lanes lanes_shift_right(poly1305_ifma_lanes a, unsigned count) {
    return _mm512_srli_epi64(a, count);
}

// Each lane of sum plus bits 51..0 of the product of bits 51..0 of the
// same lanes of x and y: VPMADD52LUQ.
static inline poly1305_ifma_lanes
lanes_multiply_add_low(poly1305_ifma_lanes sum, poly1305_ifma_lanes x, poly1305_ifma_lanes y) {
    return _mm512_madd52lo_epu64(sum, x, y);
}

// Each lane of sum plus bits 103..52 of the same product: VPMADD52HUQ.
static inline poly1305_ifma_lanes
lanes_multiply_add_high(poly1305_ifma_lanes sum, poly1305_ifma_lanes x, poly1305_ifma_lanes y) {
    return _mm512_madd52hi_epu64(sum, x, y);
}

// Lane j of b where bit j of bits is 1, and lane j of a where it is 0:
// VPBLENDMQ, which chooses each lane without a branch.
static inline poly1305_ifma_lanes lanes_select(poly1305_ifma_lane_bits bits, poly1305_ifma_lanes a,
                                               poly1305_ifma_lanes b) {
    return _mm512_mask_blend_epi64(bits, a, b);
}

// Lane j of a where bit j of bits is 1, and 0 where it is 0: VMOVDQA64
// under a zeroing mask.
static inline poly1305_ifma_lanes lanes_keep(poly1305_ifma_lane_bits bits, poly1305_ifma_lanes a) {
    return _mm512_maskz_mov_epi64(bits, a);
}

// The sum of the eight lanes modulo 2^64. _mm512_reduce_add_epi64 is no
// one instruction: the compiler adds halves of the register, then halves
// of the sum, three times.
static inline uint64_t lanes_total(poly1305_ifma_lanes a) {
    return (uint64_t)_mm512_reduce_add_epi64(a);
}

// Every vector register and k1 to k7 zeroed: avx512_wipe.h's one call, a
// block of assembly, because C names no register. poly1305_ifma.c includes
// avx512_wipe.h before its attribute push, and says why.
static inline void lanes_wipe_registers(void) {
    avx512_wipe_registers();
}

#endif // CH_CPU_RUNTIME && __x86_64__

#endif
