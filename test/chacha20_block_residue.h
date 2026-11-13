// What chacha20_block leaves on the stack, on every machine. Its state
// holds the input words, eight of them the key, and its rounds' words are
// a permutation of the state, so either gives the key. aead.c keys
// Poly1305 with it for every message, and drbg.c and quic_packet.c call
// it too. The call wipes both arrays before it returns
// (docs/decisions.md 229).
//
// block_residue_call makes one call, block_residue_snapshot copies the
// stack below its caller as deep as BLOCK_RESIDUE_BYTES, and
// run_block_residue looks in the copy, at every byte offset, for the key's
// eight words side by side and for the rounds' sixteen words side by side.
//
// Included by test/chacha20_equiv_test.c only, which declares the
// generator and the failure count this file uses, and includes this file
// before test/chacha20_equiv_residue.h, which reads the two declarations of
// test/stack_residue.c's calls below.
#ifndef CH_CHACHA20_BLOCK_RESIDUE_H
#define CH_CHACHA20_BLOCK_RESIDUE_H

#define BLOCK_RESIDUE_BYTES 4096

static uint8_t block_residue_copy[BLOCK_RESIDUE_BYTES];
static uint8_t block_residue_key[CHACHA20_KEY];
static uint8_t block_residue_nonce[CHACHA20_NONCE];
static uint32_t block_residue_counter;
static uint8_t block_residue_out[CHACHA20_BLOCK];

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);
const char *stack_residue_unsearched(void);

static __attribute__((noinline)) void block_residue_call(void) {
    chacha20_block(block_residue_key, block_residue_nonce, block_residue_counter,
                   block_residue_out);
}

static __attribute__((noinline)) void block_residue_snapshot(void) {
    volatile uint8_t below[BLOCK_RESIDUE_BYTES];
    stack_residue_take(below, BLOCK_RESIDUE_BYTES, block_residue_copy);
}

// The first byte offset in the copy where the n bytes at value sit, or
// BLOCK_RESIDUE_BYTES.
static size_t block_residue_find(const uint8_t *value, size_t n) {
    for (size_t at = 0; at + n <= BLOCK_RESIDUE_BYTES; at++) {
        if (memcmp(&block_residue_copy[at], value, n) == 0) {
            return at;
        }
    }
    return BLOCK_RESIDUE_BYTES;
}

static uint32_t block_residue_load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void run_block_residue(void) {
    const char *unsearched = stack_residue_unsearched();
    if (unsearched != NULL) {
        printf("chacha20 equivalence: SKIP the stack below chacha20_block: %s\n", unsearched);
        return;
    }
    rng_fill(block_residue_key, sizeof block_residue_key);
    rng_fill(block_residue_nonce, sizeof block_residue_nonce);
    block_residue_counter = (uint32_t)rng_next();
    block_residue_call();
    block_residue_snapshot();
    compared++;
    size_t at = block_residue_find(block_residue_key, CHACHA20_KEY);
    if (at != BLOCK_RESIDUE_BYTES) {
        failures++;
        (void)fprintf(stderr,
                      "chacha20 equivalence: residue: the stack below chacha20_block holds the "
                      "key at byte %zu of the copy\n",
                      at);
        return;
    }
    // The rounds' words are the block's keystream less the input words, in
    // the host's byte order, as the array holds them.
    uint32_t input[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    for (size_t w = 0; w < 8; w++) {
        input[4 + w] = block_residue_load32(block_residue_key + 4 * w);
    }
    input[12] = block_residue_counter;
    for (size_t w = 0; w < 3; w++) {
        input[13 + w] = block_residue_load32(block_residue_nonce + 4 * w);
    }
    uint32_t rounds[16];
    for (size_t w = 0; w < 16; w++) {
        rounds[w] = block_residue_load32(block_residue_out + 4 * w) - input[w];
    }
    compared++;
    at = block_residue_find((const uint8_t *)rounds, sizeof rounds);
    if (at != BLOCK_RESIDUE_BYTES) {
        failures++;
        (void)fprintf(stderr,
                      "chacha20 equivalence: residue: the stack below chacha20_block holds the "
                      "rounds' sixteen words at byte %zu of the copy\n",
                      at);
    }
}

#endif
