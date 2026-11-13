#include "chacha20.h"

#include "ct.h"

#ifdef CH_CPU_RUNTIME
#include "chacha20_avx2.h"
#include "chacha20_avx512.h"
#include "chacha20_vector.h"
#include "cpu_cfg.h"
#endif

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)
// Whether chacha20_xor_cpu runs chacha20_avx2.c's AVX2 kernel in place of
// chacha20_vector.c's SSE2 path: where cpu, the session's ch_cfg.cpu,
// holds CH_CPU_AVX2, which the caller sets from its own probe of the CPU.
// chapulin probes no CPU (docs/decisions.md 89 and 90).
static int use_avx2(uint32_t cpu) {
    return (cpu & CH_CPU_AVX2) != 0;
}

// Whether chacha20_xor_cpu runs chacha20_avx512.c's kernel in place of
// both paths above: where cpu holds CH_CPU_AVX512_IFMA, which says the CPU
// has AVX-512F and its operating system saves the 512-bit and mask
// registers. The kernel needs AVX-512F alone, which every CPU with AVX-512
// IFMA has, and no bit states a timing for it (docs/decisions.md 121).
static int use_avx512(uint32_t cpu) {
    return (cpu & CH_CPU_AVX512_IFMA) != 0;
}
#endif

static uint32_t rotate_left(uint32_t x, unsigned r) {
    return (x << r) | (x >> (32 - r));
}

static uint32_t load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

#define QUARTERROUND(a, b, c, d)                                                                   \
    do {                                                                                           \
        (a) += (b);                                                                                \
        (d) = rotate_left((d) ^ (a), 16);                                                          \
        (c) += (d);                                                                                \
        (b) = rotate_left((b) ^ (c), 12);                                                          \
        (a) += (b);                                                                                \
        (d) = rotate_left((d) ^ (a), 8);                                                           \
        (c) += (d);                                                                                \
        (b) = rotate_left((b) ^ (c), 7);                                                           \
    } while (0)

static void block(const uint32_t state[16], uint8_t out[CHACHA20_BLOCK]) {
    uint32_t x[16];
    for (int i = 0; i < 16; i++) {
        x[i] = state[i];
    }
    for (int i = 0; i < 10; i++) {
        QUARTERROUND(x[0], x[4], x[8], x[12]);
        QUARTERROUND(x[1], x[5], x[9], x[13]);
        QUARTERROUND(x[2], x[6], x[10], x[14]);
        QUARTERROUND(x[3], x[7], x[11], x[15]);
        QUARTERROUND(x[0], x[5], x[10], x[15]);
        QUARTERROUND(x[1], x[6], x[11], x[12]);
        QUARTERROUND(x[2], x[7], x[8], x[13]);
        QUARTERROUND(x[3], x[4], x[9], x[14]);
    }
    for (size_t i = 0; i < 16; i++) {
        uint32_t v = x[i] + state[i];
        out[4 * i] = (uint8_t)v;
        out[4 * i + 1] = (uint8_t)(v >> 8);
        out[4 * i + 2] = (uint8_t)(v >> 16);
        out[4 * i + 3] = (uint8_t)(v >> 24);
    }
}

static void setup(uint32_t state[16], const uint8_t key[CHACHA20_KEY],
                  const uint8_t nonce[CHACHA20_NONCE], uint32_t counter) {
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for (size_t i = 0; i < 8; i++) {
        state[4 + i] = load32(key + 4 * i);
    }
    state[12] = counter;
    state[13] = load32(nonce);
    state[14] = load32(nonce + 4);
    state[15] = load32(nonce + 8);
}

// The wipe of the stack below chacha20_block, and below a device object's
// chacha20_xor (docs/decisions.md 229). The state holds the key, and the
// rounds are a permutation of it, so a copy of either gives the key back.
// Each compiler keeps such copies in stack slots of its own, which no
// ct_wipe can name: gcc 15 for arm64 kept the whole state in a slot of
// block's frame. aead.c keys Poly1305 through chacha20_block for every
// message, and drbg.c and quic_packet.c call it too.
//
// So each entry calls a body that is never inlined, and then calls
// wipe_frame through wipe_frame_call, in sha3.c's form (docs/decisions.md
// 219). The frames of the body and of every call it made lay right under
// the entry's frame. wipe_frame's array lies in the same place, and the
// call writes zero over it. CHACHA20_BELOW_LEN has to cover the deepest of
// those frames under every compiler: bin/chacha20_wipe_test measures it and
// requires it inside the length, and lint-stack holds every frame of this
// file under the length and 512 bytes more. What no wipe clears: a
// register, which holds what the last instruction left in it until another
// writes it.
#define CHACHA20_BELOW_LEN 512

// The frame of this function is the array. ct_wipe is compiled apart from
// it and takes the array's address, so the compiler keeps the array in
// memory and cannot delete the call.
static void wipe_frame(void) {
    uint8_t below[CHACHA20_BELOW_LEN];
    ct_wipe(below, sizeof below);
}

// The entries call wipe_frame through this pointer, which is a volatile
// object (docs/decisions.md 91). So the compiler cannot tell which function
// the call runs and cannot compile it into the entry, where the array would
// join the entry's frame and lie above the frames it is there to wipe.
static void (*const volatile wipe_frame_call)(void) = wipe_frame;

// The body of chacha20_block, never inlined, so that its frame and block's
// lie under the entry's frame.
static __attribute__((noinline)) void block_body(const uint8_t key[CHACHA20_KEY],
                                                 const uint8_t nonce[CHACHA20_NONCE],
                                                 uint32_t counter, uint8_t out[CHACHA20_BLOCK]) {
    uint32_t state[16];
    setup(state, key, nonce, counter);
    block(state, out);
}

void chacha20_block(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                    uint32_t counter, uint8_t out[CHACHA20_BLOCK]) {
    block_body(key, nonce, counter, out);
    wipe_frame_call();
}

#ifndef CH_CPU_RUNTIME
// The body of a device object's chacha20_xor, never inlined for the
// reason block_body is. Its keystream is the last block's, which the wipe
// below the entry clears with the state.
static __attribute__((noinline)) void xor_body(const uint8_t key[CHACHA20_KEY],
                                               const uint8_t nonce[CHACHA20_NONCE],
                                               uint32_t counter, const uint8_t *in, uint8_t *out,
                                               size_t n) {
    uint32_t state[16];
    uint8_t keystream[CHACHA20_BLOCK];
    setup(state, key, nonce, counter);
    while (n > 0) {
        block(state, keystream);
        state[12]++;
        size_t take = n < CHACHA20_BLOCK ? n : CHACHA20_BLOCK;
        for (size_t i = 0; i < take; i++) {
            out[i] = in[i] ^ keystream[i];
        }
        in += take;
        out += take;
        n -= take;
    }
}
#endif

void chacha20_xor(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                  uint32_t counter, const uint8_t *in, uint8_t *out, size_t n) {
#ifdef CH_CPU_RUNTIME
    // A host object: the same keystream, several blocks at a time in
    // 128-bit vectors (chacha20_vector.h), which every CPU a host object
    // targets has. The loop below is a device object's, and the reference
    // that bin/chacha20_equiv_test compares the vector paths with.
    chacha20_vector_xor(key, nonce, counter, in, out, n);
#else
    xor_body(key, nonce, counter, in, out, n);
    wipe_frame_call();
#endif
}

#ifdef CH_CPU_RUNTIME
void chacha20_xor_cpu(uint32_t cpu, const uint8_t key[CHACHA20_KEY],
                      const uint8_t nonce[CHACHA20_NONCE], uint32_t counter, const uint8_t *in,
                      uint8_t *out, size_t n) {
#ifdef __x86_64__
    // Sixteen blocks a pass in 512-bit vectors where the session's caller
    // says the CPU has AVX-512 (chacha20_avx512.h).
    if (use_avx512(cpu)) {
        chacha20_avx512_xor(key, nonce, counter, in, out, n);
        return;
    }
    // Eight blocks a pass in 256-bit vectors where the session's caller
    // says the CPU has AVX2 (chacha20_avx2.h).
    if (use_avx2(cpu)) {
        chacha20_avx2_xor(key, nonce, counter, in, out, n);
        return;
    }
#else
    // arm64 has one vector path, so no bit picks here.
    (void)cpu;
#endif
    chacha20_vector_xor(key, nonce, counter, in, out, n);
}
#endif
