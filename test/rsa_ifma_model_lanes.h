// Test code only: the lane operations rsa_ifma_lanes.h defines on
// AVX-512 instructions, written in portable C. rsa_ifma.c includes this
// file in place of rsa_ifma_lanes.h in a unit that defines
// CH_RSA_IFMA_MODEL, and only a build with -Itest finds it, so no library
// build can read it (test/widemul-builds.sh refuses a library build that
// names the define). The kernel's own text then runs on any CPU:
// bin/rsa_ifma_model_test holds it to rsa_mont64.c on every machine, and
// bin/rsa_ifma_equiv_test holds each operation here to its instruction on
// a CPU that has AVX-512 IFMA.
//
// Each function is written from the operation section of Intel's
// pseudocode for the instruction its comment names (the Intel 64 and
// IA-32 Architectures Software Developer's Manual, volume 2), for a
// 512-bit register of eight 64-bit lanes, lane 0 in bits 63..0. A lane
// add wraps modulo 2^64, as the instruction's does.
#ifndef CH_TEST_RSA_IFMA_MODEL_LANES_H
#define CH_TEST_RSA_IFMA_MODEL_LANES_H

#include <stdint.h>

#include "ct.h"

// A 512-bit register: lane j is lanes[j].
typedef struct {
    uint64_t lane[8];
} rsa_ifma_lanes;

// A mask register of eight bits, bit j for lane j.
typedef uint8_t rsa_ifma_lane_bits;

// Bits 51..0 of a lane, the bits each multiplication reads.
#define MODEL_LOW_52_BITS ((UINT64_C(1) << 52) - 1)

// The product of bits 51..0 of x and bits 51..0 of y, at most
// (2^52 - 1)^2, which the two multiplications below add from.
static inline ct_u128 model_lane_product(uint64_t x, uint64_t y) {
    return ct_mul128(x & MODEL_LOW_52_BITS, y & MODEL_LOW_52_BITS);
}

// VPXORQ of a register with itself: every lane 0.
static inline rsa_ifma_lanes lanes_zero(void) {
    rsa_ifma_lanes result;
    for (int j = 0; j < 8; j++) {
        result.lane[j] = 0;
    }
    return result;
}

// VPBROADCASTQ: every lane value.
static inline rsa_ifma_lanes lanes_broadcast(uint64_t value) {
    rsa_ifma_lanes result;
    for (int j = 0; j < 8; j++) {
        result.lane[j] = value;
    }
    return result;
}

// VMOVDQU64 from memory: lane j is words[j].
static inline rsa_ifma_lanes lanes_load(const uint64_t *words) {
    rsa_ifma_lanes result;
    for (int j = 0; j < 8; j++) {
        result.lane[j] = words[j];
    }
    return result;
}

// VMOVDQU64 to memory: words[j] is lane j.
static inline void lanes_store(uint64_t *words, rsa_ifma_lanes lanes) {
    for (int j = 0; j < 8; j++) {
        words[j] = lanes.lane[j];
    }
}

// VPMADD52LUQ: each lane of sum plus bits 51..0 of the product of the
// same lanes of x and y.
static inline rsa_ifma_lanes lanes_multiply_add_low(rsa_ifma_lanes sum, rsa_ifma_lanes x,
                                                    rsa_ifma_lanes y) {
    for (int j = 0; j < 8; j++) {
        sum.lane[j] += (uint64_t)model_lane_product(x.lane[j], y.lane[j]) & MODEL_LOW_52_BITS;
    }
    return sum;
}

// VPMADD52HUQ: each lane of sum plus bits 103..52 of the product of the
// same lanes of x and y.
static inline rsa_ifma_lanes lanes_multiply_add_high(rsa_ifma_lanes sum, rsa_ifma_lanes x,
                                                     rsa_ifma_lanes y) {
    for (int j = 0; j < 8; j++) {
        sum.lane[j] += (uint64_t)(model_lane_product(x.lane[j], y.lane[j]) >> 52);
    }
    return sum;
}

// VALIGNQ with a count of 1: the sixteen lanes of high and low, low's
// below high's, taken from lane 1 up. Lane j of the result is lane j + 1
// of low for j below 7, and lane 7 is lane 0 of high.
static inline rsa_ifma_lanes lanes_down_one(rsa_ifma_lanes high, rsa_ifma_lanes low) {
    rsa_ifma_lanes result;
    for (int j = 0; j < 7; j++) {
        result.lane[j] = low.lane[j + 1];
    }
    result.lane[7] = high.lane[0];
    return result;
}

// VALIGNQ with a count of 7: the same sixteen lanes, taken from lane 7
// up. Lane 0 of the result is lane 7 of low, and lane j above it is lane
// j - 1 of high.
static inline rsa_ifma_lanes lanes_up_one(rsa_ifma_lanes high, rsa_ifma_lanes low) {
    rsa_ifma_lanes result;
    result.lane[0] = low.lane[7];
    for (int j = 1; j < 8; j++) {
        result.lane[j] = high.lane[j - 1];
    }
    return result;
}

// VMOVQ to a general register: lane 0.
static inline uint64_t lanes_first(rsa_ifma_lanes lanes) {
    return lanes.lane[0];
}

// VPBROADCASTQ under a mask of bit 0 alone: lanes with lane 0 replaced by
// value, and every other lane kept.
static inline rsa_ifma_lanes lanes_replace_first(rsa_ifma_lanes lanes, uint64_t value) {
    lanes.lane[0] = value;
    return lanes;
}

// VPSRLQ by 52: each lane shifted right 52 bits, zeros entering above.
static inline rsa_ifma_lanes lanes_shift_right_52(rsa_ifma_lanes lanes) {
    for (int j = 0; j < 8; j++) {
        lanes.lane[j] >>= 52;
    }
    return lanes;
}

// VPANDQ: each lane of a AND the same lane of b.
static inline rsa_ifma_lanes lanes_and(rsa_ifma_lanes a, rsa_ifma_lanes b) {
    for (int j = 0; j < 8; j++) {
        a.lane[j] &= b.lane[j];
    }
    return a;
}

// VPADDQ: each lane of a plus the same lane of b, modulo 2^64.
static inline rsa_ifma_lanes lanes_add(rsa_ifma_lanes a, rsa_ifma_lanes b) {
    for (int j = 0; j < 8; j++) {
        a.lane[j] += b.lane[j];
    }
    return a;
}

// VPCMPUQ with the predicate "not less or equal": bit j is 1 where lane j
// of a is above lane j of b, as unsigned numbers.
static inline rsa_ifma_lane_bits lanes_above(rsa_ifma_lanes a, rsa_ifma_lanes b) {
    unsigned bits = 0;
    for (int j = 0; j < 8; j++) {
        bits |= (unsigned)(a.lane[j] > b.lane[j]) << j;
    }
    return (rsa_ifma_lane_bits)bits;
}

// VPCMPUQ with the predicate "equal": bit j is 1 where lane j of a equals
// lane j of b.
static inline rsa_ifma_lane_bits lanes_equal(rsa_ifma_lanes a, rsa_ifma_lanes b) {
    unsigned bits = 0;
    for (int j = 0; j < 8; j++) {
        bits |= (unsigned)(a.lane[j] == b.lane[j]) << j;
    }
    return (rsa_ifma_lane_bits)bits;
}

// VPADDQ under a merging mask: lane j is lane j of a plus lane j of b
// where bit j of bits is 1, and lane j of source where it is 0.
static inline rsa_ifma_lanes lanes_add_where(rsa_ifma_lanes source, rsa_ifma_lane_bits bits,
                                             rsa_ifma_lanes a, rsa_ifma_lanes b) {
    for (int j = 0; j < 8; j++) {
        if (((unsigned)bits >> j) & 1U) {
            source.lane[j] = a.lane[j] + b.lane[j];
        }
    }
    return source;
}

#endif
