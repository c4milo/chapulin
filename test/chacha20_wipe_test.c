// What chacha20.c's portable entries leave on the stack (docs/decisions.md
// 229). chacha20_block and a device object's chacha20_xor each call a body
// that is never inlined and then wipe CHACHA20_BELOW_LEN bytes of the stack
// below their own frame, where the body's frames lay. A body holds the
// state, whose words 4 to 11 are the key, and the rounds, which are a
// permutation of the state, so a copy of either gives the key back.
//
// This binary is a device object's build, the form whose block keeps a
// frame of its own, and it checks three things:
//
//   - the depth: it paints the stack, calls each body by its own name with
//     no wipe after it, and requires the lowest byte the body wrote within
//     CHACHA20_BELOW_LEN of its caller, so the wipe covers the body's
//     frames;
//   - the search: a function that leaves the key in its own frame must be
//     found, so a search that could find nothing fails;
//   - the residue: after each entry, the stack below its caller holds
//     neither the key's eight words side by side nor the sixteen words of
//     the rounds of any block the call computed, side by side.
//
// This file includes chacha20.c itself, so it can call the bodies, which
// chacha20.c keeps static. The random values come from a fixed seed, so a
// run replays exactly.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chacha20.c"

#define RESIDUE_BYTES 4096
#define RESIDUE_PAINT 0xa5
// residue_paint paints this many bytes below the copy as well, so the
// copy's lowest bytes are painted wherever a compiler puts each function's
// array in its frame.
#define RESIDUE_PAINT_MARGIN 512
// Three whole blocks and 7 bytes of a fourth: the loop's last block ends
// inside the keystream buffer.
#define RESIDUE_XOR_LEN ((size_t)3 * CHACHA20_BLOCK + 7)
#define RESIDUE_XOR_BLOCKS 4

static uint64_t rng_state = UINT64_C(0x9e3779b97f4a7c15);
static int failures = 0;
static unsigned long compared = 0;

static uint64_t rng_next(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void rng_fill(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)rng_next();
    }
}

static uint8_t residue_key[CHACHA20_KEY];
static uint8_t residue_nonce[CHACHA20_NONCE];
static uint32_t residue_counter;
static uint8_t residue_in[RESIDUE_XOR_LEN];
static uint8_t residue_out[RESIDUE_XOR_LEN];
static uint8_t residue_copy[RESIDUE_BYTES];
static uint8_t residue_no_call[RESIDUE_BYTES];

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);
void stack_residue_fill(volatile uint8_t *below, size_t n, uint8_t value);
const char *stack_residue_unsearched(void);

static __attribute__((noinline)) void residue_snapshot(void) {
    volatile uint8_t below[RESIDUE_BYTES];
    stack_residue_take(below, RESIDUE_BYTES, residue_copy);
}

static __attribute__((noinline)) void residue_paint(void) {
    volatile uint8_t below[RESIDUE_BYTES + RESIDUE_PAINT_MARGIN];
    stack_residue_fill(below, sizeof below, RESIDUE_PAINT);
}

static uint32_t residue_load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// The first byte offset in the copy where the n bytes at value sit, or
// RESIDUE_BYTES.
static size_t residue_find(const void *value, size_t n) {
    for (size_t at = 0; at + n <= RESIDUE_BYTES; at++) {
        if (memcmp(&residue_copy[at], value, n) == 0) {
            return at;
        }
    }
    return RESIDUE_BYTES;
}

// How far below the top of the copy the lowest byte lies that the call
// since residue_paint wrote: a byte that no longer holds the paint, and
// that holds it where no call ran. 0 when the call wrote nothing.
static size_t residue_depth(void) {
    for (size_t i = 0; i < RESIDUE_BYTES; i++) {
        if (residue_copy[i] != RESIDUE_PAINT && residue_no_call[i] == RESIDUE_PAINT) {
            return RESIDUE_BYTES - i;
        }
    }
    return 0;
}

// The sixteen words of block's rounds for the block with this counter, in
// the host's byte order, as an array holds them: the keystream less the
// input words.
static void residue_rounds(uint32_t counter, uint32_t rounds[16]) {
    uint32_t input[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    for (size_t w = 0; w < 8; w++) {
        input[4 + w] = residue_load32(residue_key + 4 * w);
    }
    input[12] = counter;
    for (size_t w = 0; w < 3; w++) {
        input[13 + w] = residue_load32(residue_nonce + 4 * w);
    }
    uint8_t stream[CHACHA20_BLOCK];
    block_body(residue_key, residue_nonce, counter, stream);
    for (size_t w = 0; w < 16; w++) {
        rounds[w] = residue_load32(stream + 4 * w) - input[w];
    }
}

static __attribute__((noinline)) void residue_body_block(void) {
    block_body(residue_key, residue_nonce, residue_counter, residue_out);
}

static __attribute__((noinline)) void residue_body_xor(void) {
    xor_body(residue_key, residue_nonce, residue_counter, residue_in, residue_out, RESIDUE_XOR_LEN);
}

static __attribute__((noinline)) void residue_entry_block(void) {
    chacha20_block(residue_key, residue_nonce, residue_counter, residue_out);
}

static __attribute__((noinline)) void residue_entry_xor(void) {
    chacha20_xor(residue_key, residue_nonce, residue_counter, residue_in, residue_out,
                 RESIDUE_XOR_LEN);
}

// Leaves the key side by side in its own frame, as a body with no wipe
// after it may: 64 bytes into an array of 256, so the key lies deeper than
// the few bytes at the top of the snapshot's frame that its saved
// registers take.
static volatile uint8_t residue_sink;

static __attribute__((noinline)) void residue_plant(void) {
    volatile uint8_t frame[256];
    for (size_t i = 0; i < CHACHA20_KEY; i++) {
        frame[64 + i] = residue_key[i];
    }
    residue_sink = frame[64];
}

// Calls residue_plant one frame down, so its frame lies under this one's,
// as a body's frame lies under its entry's.
static __attribute__((noinline)) void residue_plant_entry(void) {
    residue_plant();
}

static void check_depth(const char *name, void (*body)(void)) {
    residue_paint();
    body();
    residue_snapshot();
    size_t depth = residue_depth();
    compared++;
    if (depth == 0 || depth > CHACHA20_BELOW_LEN) {
        failures++;
        (void)fprintf(stderr,
                      "chacha20 wipe: %s writes %zu bytes below its caller, and the wipe below "
                      "the entry covers %d\n",
                      name, depth, CHACHA20_BELOW_LEN);
        return;
    }
    printf("chacha20 wipe: %s writes %zu bytes below its caller, inside the %d the entry "
           "wipes\n",
           name, depth, CHACHA20_BELOW_LEN);
}

// The residue after an entry: the key, and the rounds of each of blocks
// blocks from the counter.
static void check_residue(const char *name, void (*entry)(void), size_t blocks) {
    entry();
    residue_snapshot();
    compared++;
    size_t at = residue_find(residue_key, CHACHA20_KEY);
    if (at != RESIDUE_BYTES) {
        failures++;
        (void)fprintf(stderr,
                      "chacha20 wipe: residue: the stack below %s holds the key at byte %zu of "
                      "the copy\n",
                      name, at);
        return;
    }
    // residue_rounds writes the stack again, and the copy stays as the
    // snapshot took it.
    for (size_t b = 0; b < blocks; b++) {
        uint32_t rounds[16];
        residue_rounds(residue_counter + (uint32_t)b, rounds);
        at = residue_find(rounds, sizeof rounds);
        if (at != RESIDUE_BYTES) {
            failures++;
            (void)fprintf(stderr,
                          "chacha20 wipe: residue: the stack below %s holds the rounds of block "
                          "%zu at byte %zu of the copy\n",
                          name, b, at);
            return;
        }
    }
}

int main(void) {
    const char *unsearched = stack_residue_unsearched();
    if (unsearched != NULL) {
        printf("chacha20 wipe: SKIP: %s\n", unsearched);
        return 0;
    }
    rng_fill(residue_key, sizeof residue_key);
    rng_fill(residue_nonce, sizeof residue_nonce);
    rng_fill(residue_in, sizeof residue_in);
    residue_counter = (uint32_t)rng_next();

    // Where no call ran, the paint stays: the bytes the snapshot's own
    // frame and the paint's leave as they are.
    residue_paint();
    residue_snapshot();
    memcpy(residue_no_call, residue_copy, sizeof residue_no_call);

    check_depth("block_body", residue_body_block);
    check_depth("xor_body", residue_body_xor);

    residue_plant_entry();
    residue_snapshot();
    compared++;
    if (residue_find(residue_key, CHACHA20_KEY) == RESIDUE_BYTES) {
        failures++;
        (void)fprintf(stderr, "chacha20 wipe: the search finds no key a function left on the "
                              "stack, so it could find nothing\n");
    }

    check_residue("chacha20_block", residue_entry_block, 1);
    check_residue("chacha20_xor", residue_entry_xor, RESIDUE_XOR_BLOCKS);

    if (failures != 0) {
        (void)fprintf(stderr, "chacha20 wipe: %d of %lu checks failed\n", failures, compared);
        return 1;
    }
    printf("chacha20 wipe: %lu checks pass: the stack below chacha20_block and chacha20_xor "
           "holds neither the key nor the rounds of a block\n",
           compared);
    return 0;
}
