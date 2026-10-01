// gcm_hw.c's gcm_counter_blocks_hw on the AES instructions, under AES-128
// and AES-256 round keys, against SP 800-38D §6.5 computed one block at a
// time on AES=soft: the same output bytes and the same counter afterwards.
// On an x86-64 CPU with VAES and VPCLMULQDQ, gcm_vaes.c's
// gcm_counter_blocks_vaes runs the same cases, which test/aes_equiv_vaes.c
// compiles (test/x86_kernels_cpu.h asks the CPU).
//
// gcm_hw.c runs GCM_HW_PASS_BLOCKS counter blocks through the rounds
// together, so the cases are chosen around that pass:
//
//   every block count from 0 to three passes and a block, which puts
//   each length of a last short pass through the loop;
//   a counter whose last four bytes are within two passes of 2^32, so
//   inc32's wrap to zero lands at every place in a pass, where a carry
//   into the twelve IV bytes would show;
//   the three layouts gcm.c passes: separate buffers, in == out, and out
//   five bytes below in, which is how record.c's open writes.
//
// Included by test/aes_equiv_test.c only, which declares the soft
// cipher, the generator and the failure count this file uses. It sits
// in a header of its own so the main stays under the file length limit.
#ifndef CH_AES_EQUIV_COUNTER_H
#define CH_AES_EQUIV_COUNTER_H

#include "x86_kernels_cpu.h"

// gcm_hw.c's entry, compiled by test/aes_equiv_hw.c under CH_AES_HW, which
// this binary's main does not define, so gcm_hw.h declares nothing here,
// and gcm_vaes.c's, compiled by test/aes_equiv_vaes.c, for the same reason.
void gcm_counter_blocks_hw(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                           const uint8_t *in, size_t blocks, uint8_t *out);
#ifdef __x86_64__
void gcm_counter_blocks_vaes(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                             const uint8_t *in, size_t blocks, uint8_t *out);
#endif

// The entry the cases run on, and its name in a mismatch.
typedef void (*counter_entry)(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                              const uint8_t *in, size_t blocks, uint8_t *out);
static counter_entry counter_blocks = gcm_counter_blocks_hw;
static const char *counter_entry_name = "gcm_counter_blocks_hw";

// gcm_hw.h's GCM_HW_PASS_BLOCKS, for the same reason.
#define COUNTER_PASS 8
#define COUNTER_MAX_BLOCKS (3 * COUNTER_PASS + 1)
// How far below its input record.c's open writes its output: the
// record header's length.
#define COUNTER_SHIFT 5

enum counter_layout { COUNTER_SEPARATE, COUNTER_IN_PLACE, COUNTER_SHIFTED, COUNTER_LAYOUTS };

static unsigned long counter_cases = 0;

static uint8_t counter_input[COUNTER_MAX_BLOCKS * AES_BLOCK];
static uint8_t counter_want[COUNTER_MAX_BLOCKS * AES_BLOCK];
static uint8_t counter_buffer[COUNTER_MAX_BLOCKS * AES_BLOCK + COUNTER_SHIFT];

// inc32 as SP 800-38D §6.2 defines it, one byte at a time with the carry:
// the last four bytes are one number, and the first twelve never change.
static void counter_increment(uint8_t counter[AES_BLOCK]) {
    for (size_t i = AES_BLOCK; i > AES_BLOCK - 4; i--) {
        counter[i - 1]++;
        if (counter[i - 1] != 0) {
            return;
        }
    }
}

// The reference: each block's counter is inc32 of the one before, and each
// output block is the input block exclusive-ored with the soft cipher of
// its counter. The keystream block is static so that this function leaves
// no keystream on the stack.
static void counter_reference(int aes256, const uint8_t *round_keys, uint8_t counter[AES_BLOCK],
                              size_t blocks) {
    static uint8_t keystream[AES_BLOCK];
    for (size_t i = 0; i < blocks; i++) {
        counter_increment(counter);
        if (aes256) {
            aes_cipher_block_256_soft(round_keys, counter, keystream);
        } else {
            aes_cipher_block_soft(round_keys, counter, keystream);
        }
        for (size_t j = 0; j < AES_BLOCK; j++) {
            counter_want[i * AES_BLOCK + j] =
                (uint8_t)(counter_input[i * AES_BLOCK + j] ^ keystream[j]);
        }
    }
}

// One case: a fresh key and input, the reference, then the instructions
// in the layout named, compared byte for byte and counter for counter.
static void compare_counter(const char *case_name, int aes256, const uint8_t start[AES_BLOCK],
                            size_t blocks, enum counter_layout layout) {
    uint8_t key[AES_256_KEY];
    uint8_t soft_keys[ROUND_KEY_BYTES_256];
    uint8_t hw_keys[ROUND_KEY_BYTES_256];
    rng_fill(key, sizeof key);
    rng_fill(counter_input, blocks * AES_BLOCK);
    if (aes256) {
        aes_expand_round_keys_256_soft(key, soft_keys);
        aes_expand_round_keys_256_hw(key, hw_keys);
    } else {
        aes_expand_round_keys_soft(key, soft_keys);
        aes_expand_round_keys_hw(key, hw_keys);
    }
    uint8_t want_counter[AES_BLOCK];
    memcpy(want_counter, start, AES_BLOCK);
    counter_reference(aes256, soft_keys, want_counter, blocks);

    uint8_t *out = counter_buffer;
    const uint8_t *in = counter_input;
    if (layout == COUNTER_IN_PLACE) {
        memcpy(counter_buffer, counter_input, blocks * AES_BLOCK);
        in = counter_buffer;
    } else if (layout == COUNTER_SHIFTED) {
        memcpy(counter_buffer + COUNTER_SHIFT, counter_input, blocks * AES_BLOCK);
        in = counter_buffer + COUNTER_SHIFT;
    }
    uint8_t counter[AES_BLOCK];
    memcpy(counter, start, AES_BLOCK);
    counter_blocks(hw_keys, aes256 ? AES_256_ROUNDS : AES_128_ROUNDS, counter, in, blocks, out);
    if (memcmp(out, counter_want, blocks * AES_BLOCK) != 0 ||
        memcmp(counter, want_counter, AES_BLOCK) != 0) {
        (void)fprintf(stderr, "FAIL %s on %s: %zu blocks, layout %d, AES-%d\n", case_name,
                      counter_entry_name, blocks, (int)layout, aes256 ? 256 : 128);
        print_hex("start  ", start, AES_BLOCK);
        print_hex("counter", counter, AES_BLOCK);
        print_hex("want   ", want_counter, AES_BLOCK);
        failures++;
        return;
    }
    counter_cases++;
}

// A counter with random IV bytes whose last four bytes read low.
static void counter_start(uint8_t start[AES_BLOCK], uint32_t low) {
    rng_fill(start, AES_BLOCK - 4);
    start[12] = (uint8_t)(low >> 24);
    start[13] = (uint8_t)(low >> 16);
    start[14] = (uint8_t)(low >> 8);
    start[15] = (uint8_t)low;
}

static void run_counter_blocks_on(counter_entry entry, const char *name) {
    counter_blocks = entry;
    counter_entry_name = name;
    uint8_t start[AES_BLOCK];
    for (int aes256 = 0; aes256 <= 1; aes256++) {
        for (int layout = 0; layout < COUNTER_LAYOUTS; layout++) {
            for (size_t blocks = 0; blocks <= COUNTER_MAX_BLOCKS; blocks++) {
                counter_start(start, 1);
                compare_counter("counter blocks by length", aes256, start, blocks,
                                (enum counter_layout)layout);
            }
            for (uint32_t k = 0; k <= 2 * COUNTER_PASS; k++) {
                counter_start(start, UINT32_MAX - k);
                compare_counter("counter blocks across the 2^32 wrap", aes256, start,
                                COUNTER_MAX_BLOCKS, (enum counter_layout)layout);
            }
        }
    }
    for (unsigned long i = 0; i < 2000 && failures == 0; i++) {
        uint32_t low = (uint32_t)rng_next();
        if (i % 2 == 0) {
            low = UINT32_MAX - (uint32_t)(rng_next() % (uint64_t)(4 * COUNTER_PASS));
        }
        counter_start(start, low);
        size_t blocks = (size_t)(rng_next() % (COUNTER_MAX_BLOCKS + 1));
        compare_counter("counter blocks random", (int)(rng_next() % 2), start, blocks,
                        (enum counter_layout)(rng_next() % COUNTER_LAYOUTS));
    }
}

// Every case on gcm_hw.c's entry, then on gcm_vaes.c's where this CPU
// runs it. Under CH_REQUIRE_X86_KERNELS a CPU without it counts as a
// failure.
static void run_counter_blocks(void) {
    run_counter_blocks_on(gcm_counter_blocks_hw, "gcm_counter_blocks_hw");
#ifdef __x86_64__
    if (x86_cpu_has_vaes()) {
        run_counter_blocks_on(gcm_counter_blocks_vaes, "gcm_counter_blocks_vaes");
    } else if (x86_kernels_required()) {
        (void)fprintf(stderr, "aes equivalence: this CPU lacks VAES or VPCLMULQDQ, and "
                              "CH_REQUIRE_X86_KERNELS is 1\n");
        failures++;
    } else {
        printf("aes equivalence: SKIP gcm_counter_blocks_vaes: this CPU lacks VAES or "
               "VPCLMULQDQ\n");
    }
#endif
}

#endif
