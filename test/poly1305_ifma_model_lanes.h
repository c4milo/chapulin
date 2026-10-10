// Test code only: the lane operations poly1305_ifma_lanes.h defines on
// AVX-512 instructions, written in portable C. poly1305_ifma.c includes
// this file in place of poly1305_ifma_lanes.h in a unit that defines
// CH_POLY1305_IFMA_MODEL, and only a build with -Itest finds it, so no
// library build can read it (test/widemul-builds.sh refuses a library
// build that names the define). The kernel's own text then runs on any
// CPU: bin/poly1305_equiv_test holds it to poly1305.c's loop on every
// machine, and holds the instructions to that loop on a CPU that has
// AVX-512 IFMA.
//
// Each function is written from the operation section of Intel's
// pseudocode for the instruction its comment names (the Intel 64 and
// IA-32 Architectures Software Developer's Manual, volume 2), for a
// 512-bit register of eight 64-bit lanes, lane 0 in bits 63..0. A lane
// add wraps modulo 2^64, as the instruction's does.
#ifndef CH_TEST_POLY1305_IFMA_MODEL_LANES_H
#define CH_TEST_POLY1305_IFMA_MODEL_LANES_H

#include <stddef.h>
#include <stdint.h>

#include "ct.h"

// A 512-bit register: lane j is lane[j].
typedef struct {
    uint64_t lane[8];
} poly1305_ifma_lanes;

// A mask register of eight bits, bit j for lane j.
typedef uint8_t poly1305_ifma_lane_bits;

// Bits 51..0 of a lane, the bits each multiplication reads.
#define MODEL_LOW_52_BITS ((UINT64_C(1) << 52) - 1)

// The product of bits 51..0 of x and bits 51..0 of y, at most
// (2^52 - 1)^2, which the two multiplications below add from.
static inline ct_u128 model_lane_product(uint64_t x, uint64_t y) {
    return ct_mul128(x & MODEL_LOW_52_BITS, y & MODEL_LOW_52_BITS);
}

// VPXORQ of a register with itself: every lane 0.
static inline poly1305_ifma_lanes lanes_zero(void) {
    poly1305_ifma_lanes result;
    for (int j = 0; j < 8; j++) {
        result.lane[j] = 0;
    }
    return result;
}

// VPBROADCASTQ: every lane value.
static inline poly1305_ifma_lanes lanes_broadcast(uint64_t value) {
    poly1305_ifma_lanes result;
    for (int j = 0; j < 8; j++) {
        result.lane[j] = value;
    }
    return result;
}

// VPBROADCASTQ under a zeroing mask of bit 0 alone: value in lane 0, and 0
// in the other seven.
static inline poly1305_ifma_lanes lanes_first_only(uint64_t value) {
    poly1305_ifma_lanes result = lanes_zero();
    result.lane[0] = value;
    return result;
}

// VPBROADCASTQ from a register: lane 0 of a in every lane.
static inline poly1305_ifma_lanes lanes_broadcast_first(poly1305_ifma_lanes a) {
    return lanes_broadcast(a.lane[0]);
}

// VMOVDQU64 from memory: lane j is bytes 8j to 8j + 7, little-endian.
static inline poly1305_ifma_lanes lanes_load_bytes(const uint8_t *bytes) {
    poly1305_ifma_lanes result;
    for (int j = 0; j < 8; j++) {
        uint64_t word = 0;
        for (int k = 7; k >= 0; k--) {
            word = (word << 8) | bytes[8 * j + k];
        }
        result.lane[j] = word;
    }
    return result;
}

// VPUNPCKLQDQ: in each 128-bit pair of lanes 2i and 2i + 1, lane 2i of a
// and then lane 2i of b.
static inline poly1305_ifma_lanes lanes_interleave_low(poly1305_ifma_lanes a,
                                                       poly1305_ifma_lanes b) {
    poly1305_ifma_lanes result;
    for (size_t i = 0; i < 4; i++) {
        result.lane[2 * i] = a.lane[2 * i];
        result.lane[2 * i + 1] = b.lane[2 * i];
    }
    return result;
}

// VPUNPCKHQDQ: in each pair, lane 2i + 1 of a and then lane 2i + 1 of b.
static inline poly1305_ifma_lanes lanes_interleave_high(poly1305_ifma_lanes a,
                                                        poly1305_ifma_lanes b) {
    poly1305_ifma_lanes result;
    for (size_t i = 0; i < 4; i++) {
        result.lane[2 * i] = a.lane[2 * i + 1];
        result.lane[2 * i + 1] = b.lane[2 * i + 1];
    }
    return result;
}

// VPADDQ: each lane of a plus the same lane of b, modulo 2^64.
static inline poly1305_ifma_lanes lanes_add(poly1305_ifma_lanes a, poly1305_ifma_lanes b) {
    for (int j = 0; j < 8; j++) {
        a.lane[j] += b.lane[j];
    }
    return a;
}

// VPANDQ.
static inline poly1305_ifma_lanes lanes_and(poly1305_ifma_lanes a, poly1305_ifma_lanes b) {
    for (int j = 0; j < 8; j++) {
        a.lane[j] &= b.lane[j];
    }
    return a;
}

// VPORQ.
static inline poly1305_ifma_lanes lanes_or(poly1305_ifma_lanes a, poly1305_ifma_lanes b) {
    for (int j = 0; j < 8; j++) {
        a.lane[j] |= b.lane[j];
    }
    return a;
}

// VPSLLQ and VPSRLQ by an immediate below 64: each lane shifted, zeros
// entering.
static inline poly1305_ifma_lanes lanes_shift_left(poly1305_ifma_lanes a, unsigned count) {
    for (int j = 0; j < 8; j++) {
        a.lane[j] <<= count;
    }
    return a;
}

static inline poly1305_ifma_lanes lanes_shift_right(poly1305_ifma_lanes a, unsigned count) {
    for (int j = 0; j < 8; j++) {
        a.lane[j] >>= count;
    }
    return a;
}

// VPMADD52LUQ: each lane of sum plus bits 51..0 of the product of the
// same lanes of x and y.
static inline poly1305_ifma_lanes
lanes_multiply_add_low(poly1305_ifma_lanes sum, poly1305_ifma_lanes x, poly1305_ifma_lanes y) {
    for (int j = 0; j < 8; j++) {
        sum.lane[j] += (uint64_t)model_lane_product(x.lane[j], y.lane[j]) & MODEL_LOW_52_BITS;
    }
    return sum;
}

// VPMADD52HUQ: each lane of sum plus bits 103..52 of the same product.
static inline poly1305_ifma_lanes
lanes_multiply_add_high(poly1305_ifma_lanes sum, poly1305_ifma_lanes x, poly1305_ifma_lanes y) {
    for (int j = 0; j < 8; j++) {
        sum.lane[j] += (uint64_t)(model_lane_product(x.lane[j], y.lane[j]) >> 52);
    }
    return sum;
}

// VPBLENDMQ: lane j of b where bit j of bits is 1, and of a where it is 0.
static inline poly1305_ifma_lanes lanes_select(poly1305_ifma_lane_bits bits, poly1305_ifma_lanes a,
                                               poly1305_ifma_lanes b) {
    for (int j = 0; j < 8; j++) {
        if (((unsigned)bits >> j) & 1U) {
            a.lane[j] = b.lane[j];
        }
    }
    return a;
}

// VMOVDQA64 under a zeroing mask: lane j of a where bit j of bits is 1,
// and 0 where it is 0.
static inline poly1305_ifma_lanes lanes_keep(poly1305_ifma_lane_bits bits, poly1305_ifma_lanes a) {
    for (int j = 0; j < 8; j++) {
        if ((((unsigned)bits >> j) & 1U) == 0) {
            a.lane[j] = 0;
        }
    }
    return a;
}

// The sum of the eight lanes modulo 2^64.
static inline uint64_t lanes_total(poly1305_ifma_lanes a) {
    uint64_t total = 0;
    for (int j = 0; j < 8; j++) {
        total += a.lane[j];
    }
    return total;
}

// avx512_wipe_registers in the instruction build. The model's lanes are
// values the compiler places in memory or registers as it does any
// other, and no instruction here names a vector register, so it has none
// to clear.
static inline void lanes_wipe_registers(void) {
}

#endif
