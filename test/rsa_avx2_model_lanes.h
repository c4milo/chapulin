// Test code only: the lane operations rsa_avx2_lanes.h defines on AVX2
// instructions, written in portable C. rsa_avx2.c includes this file in
// place of rsa_avx2_lanes.h in a unit that defines CH_RSA_AVX2_MODEL, and
// only a build with -Itest finds it, so no library build can read it
// (test/widemul-builds.sh refuses a library build that names the define).
// The kernel's own text then runs on any CPU: bin/rsa_avx2_model_test
// holds it to rsa_mont64.c on every machine, and bin/rsa_avx2_equiv_test
// holds each operation here to its instruction on a CPU that has AVX2.
//
// Each function is written from the operation section of Intel's
// pseudocode for the instruction its comment names (the Intel 64 and
// IA-32 Architectures Software Developer's Manual, volume 2), for a
// 256-bit register of four 64-bit lanes, lane 0 in bits 63..0. A lane add
// wraps modulo 2^64, as the instruction's does.
#ifndef CH_TEST_RSA_AVX2_MODEL_LANES_H
#define CH_TEST_RSA_AVX2_MODEL_LANES_H

#include <stdint.h>

// A 256-bit register: lane j is lane[j].
typedef struct {
    uint64_t lane[4];
} rsa_avx2_lanes;

// Bits 31..0 of a lane, the bits VPMULUDQ reads.
#define MODEL_LOW_32_BITS ((UINT64_C(1) << 32) - 1)

// VPXOR of a register with itself: every lane 0.
static inline rsa_avx2_lanes lanes_zero(void) {
    rsa_avx2_lanes result;
    for (int j = 0; j < 4; j++) {
        result.lane[j] = 0;
    }
    return result;
}

// VPBROADCASTQ: every lane value.
static inline rsa_avx2_lanes lanes_broadcast(uint64_t value) {
    rsa_avx2_lanes result;
    for (int j = 0; j < 4; j++) {
        result.lane[j] = value;
    }
    return result;
}

// VMOVDQU from memory: lane j is words[j].
static inline rsa_avx2_lanes lanes_load(const uint64_t *words) {
    rsa_avx2_lanes result;
    for (int j = 0; j < 4; j++) {
        result.lane[j] = words[j];
    }
    return result;
}

// VMOVDQU to memory: words[j] is lane j.
static inline void lanes_store(uint64_t *words, rsa_avx2_lanes lanes) {
    for (int j = 0; j < 4; j++) {
        words[j] = lanes.lane[j];
    }
}

// VPMULUDQ: each lane the product of bits 31..0 of the same lanes of x and
// y, which is below 2^64.
static inline rsa_avx2_lanes lanes_multiply(rsa_avx2_lanes x, rsa_avx2_lanes y) {
    rsa_avx2_lanes result;
    for (int j = 0; j < 4; j++) {
        result.lane[j] = (x.lane[j] & MODEL_LOW_32_BITS) * (y.lane[j] & MODEL_LOW_32_BITS);
    }
    return result;
}

// VPADDQ: each lane of a plus the same lane of b, modulo 2^64.
static inline rsa_avx2_lanes lanes_add(rsa_avx2_lanes a, rsa_avx2_lanes b) {
    rsa_avx2_lanes result;
    for (int j = 0; j < 4; j++) {
        result.lane[j] = a.lane[j] + b.lane[j];
    }
    return result;
}

// VPBLENDD with the mask 0x03: the two 32-bit halves of lane 0 from low,
// and lanes 1 to 3 from high.
static inline rsa_avx2_lanes lanes_first_from(rsa_avx2_lanes high, rsa_avx2_lanes low) {
    rsa_avx2_lanes result = high;
    result.lane[0] = low.lane[0];
    return result;
}

// VPBLENDD with the mask 0x30 of low over zeros, then VPBLENDD with the mask
// 0xc0 of high over that: lanes 0 and 1 zero, lane 2 from low and lane 3
// from high.
static inline rsa_avx2_lanes lanes_upper_two(rsa_avx2_lanes high, rsa_avx2_lanes low) {
    rsa_avx2_lanes result = lanes_zero();
    result.lane[2] = low.lane[2];
    result.lane[3] = high.lane[3];
    return result;
}

#endif
