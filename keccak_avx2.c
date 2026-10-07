#include "keccak_avx2.h"

// The whole file compiles only in a host object on x86-64 (keccak_avx2.h).
#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

#include <immintrin.h>

#include "keccak_round_constants.h"

// Every function from here to the pop below carries the target attribute
// that turns AVX2 on, and no function outside it does, as in
// chacha20_avx2.c: clang applies it through one attribute push, and gcc's
// target pragma sets it for each function defined after it, until the pop.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx2"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx2")
#endif

// Lane i of the four states in one AVX2 register, state k's lane in 64-bit
// lane k. Each operation below works on the four lanes at once and has no
// branch and no memory access that depends on a lane's value.
typedef __m256i lanes;

static inline lanes lanes_xor(lanes a, lanes b) {
    return _mm256_xor_si256(a, b);
}

static inline lanes lanes_xor5(lanes a, lanes b, lanes c, lanes d, lanes e) {
    return lanes_xor(lanes_xor(lanes_xor(lanes_xor(a, b), c), d), e);
}

// sha3.c's rotate_left on each lane: a shift left by r, a shift right by
// 64 - r and an OR, since AVX2 has no 64-bit rotation. r is 1 to 63 at
// every call, and a constant once the call is inlined.
static inline lanes lanes_rotate_left(lanes x, int r) {
    return _mm256_or_si256(_mm256_slli_epi64(x, r), _mm256_srli_epi64(x, 64 - r));
}

// A rotation by 8 or by 56 moves whole bytes inside each lane, so one byte
// shuffle (VPSHUFB) does it: byte i of each 16 bytes of the result is byte
// order[i] of the same 16 bytes of x. A lane's least significant byte comes
// first in memory, so a rotation left by 8 moves byte 7 to byte 0 and bytes
// 0 to 6 up one place, and a rotation left by 56 moves them down one.
static inline lanes lanes_rotate_left_8(lanes x) {
    const lanes order = _mm256_setr_epi8(7, 0, 1, 2, 3, 4, 5, 6, 15, 8, 9, 10, 11, 12, 13, 14, 7, 0,
                                         1, 2, 3, 4, 5, 6, 15, 8, 9, 10, 11, 12, 13, 14);
    return _mm256_shuffle_epi8(x, order);
}

static inline lanes lanes_rotate_left_56(lanes x) {
    const lanes order = _mm256_setr_epi8(1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8, 1, 2,
                                         3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8);
    return _mm256_shuffle_epi8(x, order);
}

// chi's step for one lane (FIPS 202 §3.2.4): b0 ^ (~b1 & b2). VPANDN
// computes ~b1 & b2 in one instruction.
static inline lanes lanes_chi(lanes b0, lanes b1, lanes b2) {
    return lanes_xor(b0, _mm256_andnot_si256(b1, b2));
}

// sha3.c's keccak_round on four states, line for line: the same theta, the
// same rotations and the same moves of rho and pi, the same chi and iota.
// sha3.c states why each step is written out.
static inline void round_x4(lanes a[25], lanes round_constant) {
    lanes c0 = lanes_xor5(a[0], a[5], a[10], a[15], a[20]);
    lanes c1 = lanes_xor5(a[1], a[6], a[11], a[16], a[21]);
    lanes c2 = lanes_xor5(a[2], a[7], a[12], a[17], a[22]);
    lanes c3 = lanes_xor5(a[3], a[8], a[13], a[18], a[23]);
    lanes c4 = lanes_xor5(a[4], a[9], a[14], a[19], a[24]);
    lanes d0 = lanes_xor(c4, lanes_rotate_left(c1, 1));
    lanes d1 = lanes_xor(c0, lanes_rotate_left(c2, 1));
    lanes d2 = lanes_xor(c1, lanes_rotate_left(c3, 1));
    lanes d3 = lanes_xor(c2, lanes_rotate_left(c4, 1));
    lanes d4 = lanes_xor(c3, lanes_rotate_left(c0, 1));

    a[0] = lanes_xor(a[0], d0);
    a[5] = lanes_xor(a[5], d0);
    a[10] = lanes_xor(a[10], d0);
    a[15] = lanes_xor(a[15], d0);
    a[20] = lanes_xor(a[20], d0);
    a[1] = lanes_xor(a[1], d1);
    a[6] = lanes_xor(a[6], d1);
    a[11] = lanes_xor(a[11], d1);
    a[16] = lanes_xor(a[16], d1);
    a[21] = lanes_xor(a[21], d1);
    a[2] = lanes_xor(a[2], d2);
    a[7] = lanes_xor(a[7], d2);
    a[12] = lanes_xor(a[12], d2);
    a[17] = lanes_xor(a[17], d2);
    a[22] = lanes_xor(a[22], d2);
    a[3] = lanes_xor(a[3], d3);
    a[8] = lanes_xor(a[8], d3);
    a[13] = lanes_xor(a[13], d3);
    a[18] = lanes_xor(a[18], d3);
    a[23] = lanes_xor(a[23], d3);
    a[4] = lanes_xor(a[4], d4);
    a[9] = lanes_xor(a[9], d4);
    a[14] = lanes_xor(a[14], d4);
    a[19] = lanes_xor(a[19], d4);
    a[24] = lanes_xor(a[24], d4);

    lanes b0 = a[0];
    lanes b1 = lanes_rotate_left(a[6], 44);
    lanes b2 = lanes_rotate_left(a[12], 43);
    lanes b3 = lanes_rotate_left(a[18], 21);
    lanes b4 = lanes_rotate_left(a[24], 14);

    lanes b5 = lanes_rotate_left(a[3], 28);
    lanes b6 = lanes_rotate_left(a[9], 20);
    lanes b7 = lanes_rotate_left(a[10], 3);
    lanes b8 = lanes_rotate_left(a[16], 45);
    lanes b9 = lanes_rotate_left(a[22], 61);

    lanes b10 = lanes_rotate_left(a[1], 1);
    lanes b11 = lanes_rotate_left(a[7], 6);
    lanes b12 = lanes_rotate_left(a[13], 25);
    lanes b13 = lanes_rotate_left_8(a[19]);
    lanes b14 = lanes_rotate_left(a[20], 18);

    lanes b15 = lanes_rotate_left(a[4], 27);
    lanes b16 = lanes_rotate_left(a[5], 36);
    lanes b17 = lanes_rotate_left(a[11], 10);
    lanes b18 = lanes_rotate_left(a[17], 15);
    lanes b19 = lanes_rotate_left_56(a[23]);

    lanes b20 = lanes_rotate_left(a[2], 62);
    lanes b21 = lanes_rotate_left(a[8], 55);
    lanes b22 = lanes_rotate_left(a[14], 39);
    lanes b23 = lanes_rotate_left(a[15], 41);
    lanes b24 = lanes_rotate_left(a[21], 2);

    a[0] = lanes_chi(b0, b1, b2);
    a[1] = lanes_chi(b1, b2, b3);
    a[2] = lanes_chi(b2, b3, b4);
    a[3] = lanes_chi(b3, b4, b0);
    a[4] = lanes_chi(b4, b0, b1);
    a[5] = lanes_chi(b5, b6, b7);
    a[6] = lanes_chi(b6, b7, b8);
    a[7] = lanes_chi(b7, b8, b9);
    a[8] = lanes_chi(b8, b9, b5);
    a[9] = lanes_chi(b9, b5, b6);
    a[10] = lanes_chi(b10, b11, b12);
    a[11] = lanes_chi(b11, b12, b13);
    a[12] = lanes_chi(b12, b13, b14);
    a[13] = lanes_chi(b13, b14, b10);
    a[14] = lanes_chi(b14, b10, b11);
    a[15] = lanes_chi(b15, b16, b17);
    a[16] = lanes_chi(b16, b17, b18);
    a[17] = lanes_chi(b17, b18, b19);
    a[18] = lanes_chi(b18, b19, b15);
    a[19] = lanes_chi(b19, b15, b16);
    a[20] = lanes_chi(b20, b21, b22);
    a[21] = lanes_chi(b21, b22, b23);
    a[22] = lanes_chi(b22, b23, b24);
    a[23] = lanes_chi(b23, b24, b20);
    a[24] = lanes_chi(b24, b20, b21);

    a[0] = lanes_xor(a[0], round_constant);
}

void keccak_avx2_permute(keccak_x4 *s) {
    lanes a[25];
    for (size_t i = 0; i < 25; i++) {
        a[i] = _mm256_load_si256((const __m256i *)(const void *)s->lane[i]);
    }
    for (size_t round = 0; round < 24; round++) {
        // The cast keeps the constant's 64 bits, which is how gcc and clang
        // define the conversion of a value above LLONG_MAX.
        round_x4(a, _mm256_set1_epi64x((long long)RC[round]));
    }
    for (size_t i = 0; i < 25; i++) {
        _mm256_store_si256((__m256i *)(void *)s->lane[i], a[i]);
    }
}

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif

// Eight bytes as one lane, least significant byte first (FIPS 202 §3.1.2),
// named one by one, as sha3.c's lane_from_bytes reads them.
static uint64_t lane_from_bytes(const uint8_t b[8]) {
    return (uint64_t)b[0] | ((uint64_t)b[1] << 8) | ((uint64_t)b[2] << 16) |
           ((uint64_t)b[3] << 24) | ((uint64_t)b[4] << 32) | ((uint64_t)b[5] << 40) |
           ((uint64_t)b[6] << 48) | ((uint64_t)b[7] << 56);
}

// Each state's one block, as sha3.c's absorb and pad_finish leave a SHAKE128
// context that absorbed 34 bytes: the 32 seed bytes in lanes 0 to 3, the two
// indices in the low two bytes of lane 4, SHAKE's domain bits with the first
// pad bit, 0x1f (sha3.c's SHAKE_DOMAIN), in the byte after them, and the
// last pad bit, 0x80, in byte SHAKE128_RATE - 1, the top byte of lane 20
// (FIPS 202 §B.2). Every other lane is zero.
void keccak_avx2_shake128_start(keccak_x4 *s, const uint8_t seed[32], const uint8_t x0[4],
                                const uint8_t x1[4]) {
    for (size_t i = 0; i < 25; i++) {
        for (size_t k = 0; k < 4; k++) {
            s->lane[i][k] = 0;
        }
    }
    for (size_t k = 0; k < 4; k++) {
        for (size_t i = 0; i < 4; i++) {
            s->lane[i][k] = lane_from_bytes(seed + 8 * i);
        }
        s->lane[4][k] = (uint64_t)x0[k] | ((uint64_t)x1[k] << 8) | ((uint64_t)0x1f << 16);
        s->lane[20][k] = (uint64_t)0x80 << 56;
    }
    keccak_avx2_permute(s);
}

// Lane i of state k as its eight bytes, named one by one so that a
// compiler writes them with one store (docs/performance.md).
void keccak_avx2_block(uint8_t out[SHAKE128_RATE], const keccak_x4 *s, unsigned k) {
    for (size_t i = 0; i < 21; i++) {
        uint64_t lane = s->lane[i][k];
        uint8_t *b = out + 8 * i;
        b[0] = (uint8_t)lane;
        b[1] = (uint8_t)(lane >> 8);
        b[2] = (uint8_t)(lane >> 16);
        b[3] = (uint8_t)(lane >> 24);
        b[4] = (uint8_t)(lane >> 32);
        b[5] = (uint8_t)(lane >> 40);
        b[6] = (uint8_t)(lane >> 48);
        b[7] = (uint8_t)(lane >> 56);
    }
}

#endif // CH_CPU_RUNTIME && __x86_64__
