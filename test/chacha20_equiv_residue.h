// What chacha20_vector_xor leaves on the stack on NEON. Its frame holds
// the input words, eight of them the key, and a NEON pass computes one
// block in general registers beside its two groups, whose 16 words start
// as the input and end as the block's keystream before the input is added
// back (docs/decisions.md 193). The call wipes the input words and the
// buffer its last 1 to 15 bytes pass through before it returns. The frame
// is dead after the return, but its bytes stay in memory below this
// binary's own frames until another call writes over them.
//
// residue_call makes one call over RESIDUE_LENGTH bytes, one whole pass
// and part of a second, whose last row ends inside the block in general
// registers. residue_snapshot copies the stack below its caller as deep as
// RESIDUE_BYTES, where the dead frame lay, and run_residue looks in the
// copy, at every byte offset, for two things:
//
//   the key's eight words side by side, as the input words and the block
//   in general registers hold them;
//   each word of each block in general registers the call computed,
//   before and after the input is added back, alone, as a spill slot of a
//   general register would hold it.
//
// The second search takes 64 words to 8,189 offsets, so a word of random
// bytes matches by chance about once in 8,000 runs, and the seed is fixed.
//
// The search finds no key word alone. A group's vectors start as the input
// words, one word in all four lanes, and the compilers keep some of them
// in spill slots that no wipe written in C can name (docs/decisions.md
// 86): Apple clang 21 left key word 4 in four lanes there. Only the NEON
// arm runs a block in general registers, and the search runs on it alone.
//
// Included by test/chacha20_equiv_test.c only, which declares the
// generator, the failure count and the current path this file uses.
#ifndef CH_CHACHA20_EQUIV_RESIDUE_H
#define CH_CHACHA20_EQUIV_RESIDUE_H

#ifdef __ARM_NEON

// Two NEON passes of nine blocks less 7 bytes: the second pass's last row
// ends 9 bytes into the block in general registers.
#define RESIDUE_PASS_BYTES ((size_t)9 * CHACHA20_BLOCK)
#define RESIDUE_LENGTH (2 * RESIDUE_PASS_BYTES - 7)
#define RESIDUE_BYTES 8192

static uint8_t residue_copy[RESIDUE_BYTES];
static uint8_t residue_key[CHACHA20_KEY];
static uint8_t residue_nonce[CHACHA20_NONCE];
static uint32_t residue_counter;
static uint8_t residue_in[RESIDUE_LENGTH];
static uint8_t residue_out[RESIDUE_LENGTH];

static __attribute__((noinline)) void residue_call(void) {
    chacha20_vector_xor(residue_key, residue_nonce, residue_counter, residue_in, residue_out,
                        RESIDUE_LENGTH);
}

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);
const char *stack_residue_unsearched(void);

static __attribute__((noinline)) void residue_snapshot(void) {
    volatile uint8_t below[RESIDUE_BYTES];
    stack_residue_take(below, RESIDUE_BYTES, residue_copy);
}

static uint32_t residue_load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// The first byte offset in the copy where word sits, or RESIDUE_BYTES.
static size_t residue_find(uint32_t word) {
    for (size_t at = 0; at + 4 <= RESIDUE_BYTES; at++) {
        if (residue_load32(&residue_copy[at]) == word) {
            return at;
        }
    }
    return RESIDUE_BYTES;
}

// The first byte offset in the copy where the key's eight words sit side
// by side, or RESIDUE_BYTES.
static size_t residue_find_key(void) {
    for (size_t at = 0; at + CHACHA20_KEY <= RESIDUE_BYTES; at++) {
        if (memcmp(&residue_copy[at], residue_key, CHACHA20_KEY) == 0) {
            return at;
        }
    }
    return RESIDUE_BYTES;
}

static void residue_report(const char *what, size_t index, size_t at) {
    failures++;
    (void)fprintf(stderr,
                  "chacha20 equivalence: residue: the stack below the call still holds %s word "
                  "%zu, at byte %zu of the copy\n",
                  what, index, at);
}

static void run_residue(void) {
    const char *unsearched = stack_residue_unsearched();
    if (unsearched != NULL) {
        printf("chacha20 equivalence: SKIP the stack residue: %s\n", unsearched);
        return;
    }
    rng_fill(residue_key, sizeof residue_key);
    rng_fill(residue_nonce, sizeof residue_nonce);
    rng_fill(residue_in, sizeof residue_in);
    residue_counter = (uint32_t)rng_next();
    residue_call();
    residue_snapshot();
    compared++;
    size_t key_at = residue_find_key();
    if (key_at != RESIDUE_BYTES) {
        residue_report("the key, eight words side by side from", 0, key_at);
        return;
    }
    // The block in general registers is block 8 of each pass. Its words
    // after the rounds are the keystream less the input.
    for (uint32_t p = 0; p < 2; p++) {
        uint32_t counter = residue_counter + 9 * p + 8;
        uint8_t block[CHACHA20_BLOCK];
        chacha20_block(residue_key, residue_nonce, counter, block);
        uint32_t input[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
        for (size_t w = 0; w < 8; w++) {
            input[4 + w] = residue_load32(residue_key + 4 * w);
        }
        input[12] = counter;
        for (size_t w = 0; w < 3; w++) {
            input[13 + w] = residue_load32(residue_nonce + 4 * w);
        }
        for (size_t w = 0; w < 16; w++) {
            uint32_t word = residue_load32(block + 4 * w);
            size_t at = residue_find(word);
            if (at != RESIDUE_BYTES) {
                residue_report("the keystream of a block in general registers,", w, at);
                return;
            }
            at = residue_find(word - input[w]);
            if (at != RESIDUE_BYTES) {
                residue_report("the rounds' output of a block in general registers,", w, at);
                return;
            }
        }
    }
    printf("chacha20 equivalence: the stack below the 128-bit path holds neither the key's "
           "words side by side nor a word of its blocks in general registers\n");
}

#endif // __ARM_NEON

#endif
