// Test code only: the lane operations chacha20_avx512_lanes.h defines on
// AVX-512F instructions, written in portable C. chacha20_avx512_lanes.h
// includes this file in place of its instructions in a unit that defines
// CH_CHACHA20_AVX512_MODEL, and only a build with -Itest finds it, so no
// library build can read it (test/widemul-builds.sh refuses a library build
// that names the define). aead_avx512.c's own text then runs on any CPU:
// bin/aead_avx512_equiv_test holds it to the two-pass AEAD on every
// machine, and the aead_avx512 harnesses read it.
//
// Each function is written from the operation section of Intel's
// pseudocode for the instruction its comment names (the Intel 64 and
// IA-32 Architectures Software Developer's Manual, volume 2), for a
// 512-bit register of sixteen 32-bit lanes, lane 0 in bits 31..0. A
// 128-bit quarter q holds lanes 4q to 4q + 3. A lane add wraps modulo
// 2^32, as the instruction's does.
#ifndef CH_TEST_CHACHA20_AVX512_MODEL_LANES_H
#define CH_TEST_CHACHA20_AVX512_MODEL_LANES_H

#include <stddef.h>
#include <stdint.h>

// A 512-bit register: lane j is lane[j].
typedef struct {
    uint32_t lane[16];
} chacha_lanes;

// VPBROADCASTD: every lane word.
static inline chacha_lanes chacha_lanes_broadcast(uint32_t word) {
    chacha_lanes result;
    for (int j = 0; j < 16; j++) {
        result.lane[j] = word;
    }
    return result;
}

// VPXORD of a register with itself: every lane 0.
static inline chacha_lanes chacha_lanes_zero(void) {
    return chacha_lanes_broadcast(0);
}

// VPADDD.
static inline chacha_lanes chacha_lanes_add(chacha_lanes a, chacha_lanes b) {
    chacha_lanes result;
    for (int j = 0; j < 16; j++) {
        result.lane[j] = a.lane[j] + b.lane[j];
    }
    return result;
}

// VPXORD.
static inline chacha_lanes chacha_lanes_xor(chacha_lanes a, chacha_lanes b) {
    chacha_lanes result;
    for (int j = 0; j < 16; j++) {
        result.lane[j] = a.lane[j] ^ b.lane[j];
    }
    return result;
}

// VPROLD by count, 1 to 31.
static inline chacha_lanes chacha_lanes_model_rotate(chacha_lanes x, unsigned count) {
    chacha_lanes result;
    for (int j = 0; j < 16; j++) {
        result.lane[j] = (x.lane[j] << count) | (x.lane[j] >> (32 - count));
    }
    return result;
}

static inline chacha_lanes chacha_lanes_rotate_left_16(chacha_lanes x) {
    return chacha_lanes_model_rotate(x, 16);
}

static inline chacha_lanes chacha_lanes_rotate_left_12(chacha_lanes x) {
    return chacha_lanes_model_rotate(x, 12);
}

static inline chacha_lanes chacha_lanes_rotate_left_8(chacha_lanes x) {
    return chacha_lanes_model_rotate(x, 8);
}

static inline chacha_lanes chacha_lanes_rotate_left_7(chacha_lanes x) {
    return chacha_lanes_model_rotate(x, 7);
}

// VPBROADCASTD and VPADDD of the constant 0 to 15: counter + j in lane j.
static inline chacha_lanes chacha_lanes_counters(uint32_t counter) {
    chacha_lanes result;
    for (int j = 0; j < 16; j++) {
        result.lane[j] = counter + (uint32_t)j;
    }
    return result;
}

// VPUNPCKLDQ: in quarter q, lanes 0 and 1 of a and b in the order a0 b0 a1
// b1. high selects VPUNPCKHDQ, which takes lanes 2 and 3.
static inline chacha_lanes chacha_lanes_model_interleave_32(chacha_lanes a, chacha_lanes b,
                                                            int high) {
    chacha_lanes result;
    for (size_t q = 0; q < 4; q++) {
        size_t from = 4 * q + 2 * (size_t)high;
        result.lane[4 * q] = a.lane[from];
        result.lane[4 * q + 1] = b.lane[from];
        result.lane[4 * q + 2] = a.lane[from + 1];
        result.lane[4 * q + 3] = b.lane[from + 1];
    }
    return result;
}

static inline chacha_lanes chacha_lanes_interleave_low_32(chacha_lanes a, chacha_lanes b) {
    return chacha_lanes_model_interleave_32(a, b, 0);
}

static inline chacha_lanes chacha_lanes_interleave_high_32(chacha_lanes a, chacha_lanes b) {
    return chacha_lanes_model_interleave_32(a, b, 1);
}

// VPUNPCKLQDQ: in quarter q, the low 64 bits of a then the low 64 bits of
// b. high selects VPUNPCKHQDQ, which takes the high 64 bits of each.
static inline chacha_lanes chacha_lanes_model_interleave_64(chacha_lanes a, chacha_lanes b,
                                                            int high) {
    chacha_lanes result;
    for (size_t q = 0; q < 4; q++) {
        size_t from = 4 * q + 2 * (size_t)high;
        result.lane[4 * q] = a.lane[from];
        result.lane[4 * q + 1] = a.lane[from + 1];
        result.lane[4 * q + 2] = b.lane[from];
        result.lane[4 * q + 3] = b.lane[from + 1];
    }
    return result;
}

static inline chacha_lanes chacha_lanes_interleave_low_64(chacha_lanes a, chacha_lanes b) {
    return chacha_lanes_model_interleave_64(a, b, 0);
}

static inline chacha_lanes chacha_lanes_interleave_high_64(chacha_lanes a, chacha_lanes b) {
    return chacha_lanes_model_interleave_64(a, b, 1);
}

// VSHUFI32X4 under the constant order: quarter 0 of the result is quarter
// order[1:0] of a, quarter 1 quarter order[3:2] of a, quarter 2 quarter
// order[5:4] of b, and quarter 3 quarter order[7:6] of b.
static inline chacha_lanes chacha_lanes_model_quarters(chacha_lanes a, chacha_lanes b,
                                                       unsigned order) {
    chacha_lanes result;
    for (unsigned q = 0; q < 4; q++) {
        unsigned from = (order >> (2 * q)) & 3;
        const chacha_lanes *source = q < 2 ? &a : &b;
        for (unsigned i = 0; i < 4; i++) {
            result.lane[4 * q + i] = source->lane[4 * from + i];
        }
    }
    return result;
}

static inline chacha_lanes chacha_lanes_quarters_0101(chacha_lanes a, chacha_lanes b) {
    return chacha_lanes_model_quarters(a, b, 0x44);
}

static inline chacha_lanes chacha_lanes_quarters_2323(chacha_lanes a, chacha_lanes b) {
    return chacha_lanes_model_quarters(a, b, 0xee);
}

static inline chacha_lanes chacha_lanes_quarters_0202(chacha_lanes a, chacha_lanes b) {
    return chacha_lanes_model_quarters(a, b, 0x88);
}

static inline chacha_lanes chacha_lanes_quarters_1313(chacha_lanes a, chacha_lanes b) {
    return chacha_lanes_model_quarters(a, b, 0xdd);
}

// VPSHUFD under the constant order: in each quarter, lane i of the result
// is lane order[2i + 1:2i] of the same quarter of x.
static inline chacha_lanes chacha_lanes_model_turn(chacha_lanes x, unsigned order) {
    chacha_lanes result;
    for (unsigned q = 0; q < 4; q++) {
        for (unsigned i = 0; i < 4; i++) {
            result.lane[4 * q + i] = x.lane[4 * q + ((order >> (2 * i)) & 3)];
        }
    }
    return result;
}

static inline chacha_lanes chacha_lanes_turn_1(chacha_lanes x) {
    return chacha_lanes_model_turn(x, 0x39);
}

static inline chacha_lanes chacha_lanes_turn_2(chacha_lanes x) {
    return chacha_lanes_model_turn(x, 0x4e);
}

static inline chacha_lanes chacha_lanes_turn_3(chacha_lanes x) {
    return chacha_lanes_model_turn(x, 0x93);
}

// VBROADCASTI32X4: word i in lane 4q + i of every quarter q.
static inline chacha_lanes chacha_lanes_row(const uint32_t words[4]) {
    chacha_lanes result;
    for (size_t q = 0; q < 4; q++) {
        for (size_t i = 0; i < 4; i++) {
            result.lane[4 * q + i] = words[i];
        }
    }
    return result;
}

// VBROADCASTI32X4 of (counter, nonce[0], nonce[1], nonce[2]) and VPADDD of q
// in lane 4q.
static inline chacha_lanes chacha_lanes_row_counters(uint32_t counter, const uint32_t nonce[3]) {
    chacha_lanes result;
    for (size_t q = 0; q < 4; q++) {
        result.lane[4 * q] = counter + (uint32_t)q;
        result.lane[4 * q + 1] = nonce[0];
        result.lane[4 * q + 2] = nonce[1];
        result.lane[4 * q + 3] = nonce[2];
    }
    return result;
}

// VMOVDQU32 from memory: lane j from bytes 4j to 4j + 3, little-endian.
static inline chacha_lanes chacha_lanes_load(const uint8_t *bytes) {
    chacha_lanes result;
    for (size_t j = 0; j < 16; j++) {
        const uint8_t *b = bytes + 4 * j;
        result.lane[j] = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
                         ((uint32_t)b[3] << 24);
    }
    return result;
}

// VMOVDQU32 to memory: lane j to bytes 4j to 4j + 3, little-endian.
static inline void chacha_lanes_store(uint8_t *bytes, chacha_lanes x) {
    for (size_t j = 0; j < 16; j++) {
        uint8_t *b = bytes + 4 * j;
        b[0] = (uint8_t)x.lane[j];
        b[1] = (uint8_t)(x.lane[j] >> 8);
        b[2] = (uint8_t)(x.lane[j] >> 16);
        b[3] = (uint8_t)(x.lane[j] >> 24);
    }
}

// avx512_wipe_registers has no register to clear in the model.
static inline void chacha_lanes_wipe_registers(void) {
}

#endif
