#include "keccak_neon.h"

// The whole file compiles only in a host object on arm64 (keccak_neon.h). On any other target
// it holds nothing: <stdint.h> is there through the header, so it is a translation unit still.
#if defined(CH_CPU_RUNTIME) && defined(__aarch64__)

#include <arm_neon.h>

#include "keccak_round_constants.h"

// The plain NEON form. Each operation is one to three instructions that every arm64 CPU has: a
// rotation is a shift left (SHL) and a shift right and insert (SRI), x & ~y is BIC. Each works
// on both lanes at once and has no branch and no memory access that depends on a lane's value.
// kn_xar is a macro because SHL and SRI take their shift as an immediate.
static inline uint64x2_t kn_xor3_plain(uint64x2_t x, uint64x2_t y, uint64x2_t z) {
    return veorq_u64(veorq_u64(x, y), z);
}

static inline uint64x2_t kn_rax1_plain(uint64x2_t x, uint64x2_t y) {
    return veorq_u64(x, vsriq_n_u64(vshlq_n_u64(y, 1), y, 63));
}

static inline uint64x2_t kn_bcax_plain(uint64x2_t x, uint64x2_t y, uint64x2_t z) {
    return veorq_u64(x, vbicq_u64(y, z));
}

#define KN_ROTATE_PLAIN(t, r) vsriq_n_u64(vshlq_n_u64((t), (r)), (t), 64 - (r))

#define KN_PERMUTE keccak_neon_permute
#define kn_xor3 kn_xor3_plain
#define kn_rax1 kn_rax1_plain
#define kn_xar(x, y, r) KN_ROTATE_PLAIN(veorq_u64((x), (y)), r)
#define kn_bcax kn_bcax_plain
#include "keccak_neon_round.h"
#undef KN_PERMUTE
#undef kn_xor3
#undef kn_rax1
#undef kn_xar
#undef kn_bcax

#ifdef CH_KECCAK_INSTRUCTIONS
// The form on FEAT_SHA3's instructions, as sha3_hw.c's round runs them on one state. The
// pragma puts the target attribute that turns them on onto each function defined until the pop
// below, and on no function outside it, so the rest of the object runs on any arm64 CPU.
#pragma clang attribute push(__attribute__((target("sha3"))), apply_to = function)

#define KN_PERMUTE keccak_neon_permute_sha3
#define kn_xor3 veor3q_u64
#define kn_rax1 vrax1q_u64
#define kn_xar(x, y, r) vxarq_u64((x), (y), 64 - (r))
#define kn_bcax vbcaxq_u64
#include "keccak_neon_round.h"
#undef KN_PERMUTE
#undef kn_xor3
#undef kn_rax1
#undef kn_xar
#undef kn_bcax

#pragma clang attribute pop
#endif // CH_KECCAK_INSTRUCTIONS

// Eight bytes as one lane, least significant byte first (FIPS 202 §3.1.2), named one by one,
// as sha3.c's lane_from_bytes reads them.
static uint64_t lane_from_bytes(const uint8_t b[8]) {
    return (uint64_t)b[0] | ((uint64_t)b[1] << 8) | ((uint64_t)b[2] << 16) |
           ((uint64_t)b[3] << 24) | ((uint64_t)b[4] << 32) | ((uint64_t)b[5] << 40) |
           ((uint64_t)b[6] << 48) | ((uint64_t)b[7] << 56);
}

// Each state's one block, as sha3.c's absorb and pad_finish leave a SHAKE128 context that
// absorbed 34 bytes: the 32 seed bytes in lanes 0 to 3, the two indices in the low two bytes of
// lane 4, SHAKE's domain bits with the first pad bit, 0x1f (sha3.c's SHAKE_DOMAIN), in the
// byte after them, and the last pad bit, 0x80, in byte SHAKE128_RATE - 1, the top byte of lane
// 20 (FIPS 202 §B.2). Every other lane is zero. keccak_avx2.c writes the same block.
void keccak_neon_shake128_absorb(keccak_x2 *s, const uint8_t seed[32], const uint8_t x0[2],
                                 const uint8_t x1[2]) {
    for (size_t i = 0; i < 25; i++) {
        s->lane[i][0] = 0;
        s->lane[i][1] = 0;
    }
    for (size_t k = 0; k < 2; k++) {
        for (size_t i = 0; i < 4; i++) {
            s->lane[i][k] = lane_from_bytes(seed + 8 * i);
        }
        s->lane[4][k] = (uint64_t)x0[k] | ((uint64_t)x1[k] << 8) | ((uint64_t)0x1f << 16);
        s->lane[20][k] = (uint64_t)0x80 << 56;
    }
}

// Lane i of state k as its eight bytes, named one by one so that a compiler writes them with
// one store (docs/performance.md).
void keccak_neon_block(uint8_t out[SHAKE128_RATE], const keccak_x2 *s, unsigned k) {
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

#endif // CH_CPU_RUNTIME && __aarch64__
