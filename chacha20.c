#include "chacha20.h"

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

void chacha20_block(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                    uint32_t counter, uint8_t out[CHACHA20_BLOCK]) {
    uint32_t state[16];
    setup(state, key, nonce, counter);
    block(state, out);
}

void chacha20_xor(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                  uint32_t counter, const uint8_t *in, uint8_t *out, size_t n) {
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
