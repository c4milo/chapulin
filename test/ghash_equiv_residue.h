// What gcm_hash_data_hw leaves on the stack. ghash_hw.c computes the
// powers of the hash subkey it needs, keeps them in its ghash_state on
// its frame beside the subkey and the sums each pass adds up, and wipes
// that state once when the call ends. The frame is dead after the
// return, but its bytes stay in memory below this binary's own frames
// until another call writes over them.
//
// residue_call makes one call over three passes of data, residue_snapshot
// copies the stack below its caller as deep as RESIDUE_BYTES, where the
// dead frame lay, and run_residue looks in the copy for two things:
//
//   H and every power of it the call computed, in the layout ghash_state
//   holds them: the high word, then the low word, each in the host's byte
//   order;
//   the three sums the last pass leaves in ghash_state, the carry-less
//   products of its blocks and the powers of H before the reduction, each
//   as bits 0 to 63 and then bits 64 to 127, in the host's byte order.
//
// The portable multiply and residue_carryless_multiply compute them only
// after the copy, so their own frames cannot hold them first.
//
// Included by test/ghash_equiv_test.c only, which declares the portable
// multiply and data loop, the generator and the failure count this file
// uses.
#ifndef CH_GHASH_EQUIV_RESIDUE_H
#define CH_GHASH_EQUIV_RESIDUE_H

// ghash_hw.c's GHASH_PASS_BLOCKS, which this binary does not include.
#define RESIDUE_POWERS 8
#define RESIDUE_PASSES 3
#define RESIDUE_BYTES 4096

static uint8_t residue_copy[RESIDUE_BYTES];
static uint8_t residue_data[RESIDUE_PASSES * RESIDUE_POWERS * AES_BLOCK];
static uint8_t residue_acc[AES_BLOCK]; // the accumulator the call starts from
static uint8_t residue_result[AES_BLOCK];
static uint8_t residue_subkey[AES_BLOCK];

static __attribute__((noinline)) void residue_call(void) {
    memcpy(residue_result, residue_acc, AES_BLOCK);
    gcm_hash_data_hw(residue_result, residue_subkey, residue_data, sizeof residue_data);
}

// test/stack_residue.c, compiled as a source of its own.
void stack_residue_take(volatile uint8_t *below, size_t n, uint8_t *copy);

static __attribute__((noinline)) void residue_snapshot(void) {
    volatile uint8_t below[RESIDUE_BYTES];
    stack_residue_take(below, RESIDUE_BYTES, residue_copy);
}

// The two 64-bit words of a block SP 800-38D writes as 16 big-endian
// bytes: words[0] reads bytes 0 to 7, the high word, and words[1] bytes 8
// to 15, the low word.
static void residue_words(const uint8_t block[AES_BLOCK], uint64_t words[2]) {
    words[0] = 0;
    words[1] = 0;
    for (size_t i = 0; i < 8; i++) {
        words[0] = (words[0] << 8) | block[i];
        words[1] = (words[1] << 8) | block[8 + i];
    }
}

// product ^= the 128-bit carry-less product of a and b, bits 0 to 63 in
// product[0].
static void residue_carryless_multiply(uint64_t a, uint64_t b, uint64_t product[2]) {
    for (unsigned i = 0; i < 64; i++) {
        if ((b >> i) & 1U) {
            product[0] ^= a << i;
            if (i > 0) {
                product[1] ^= a >> (64 - i);
            }
        }
    }
}

// Whether the copy holds the 16 bytes two words make in memory.
static int residue_holds(const uint64_t words[2]) {
    uint8_t layout[AES_BLOCK];
    memcpy(layout, words, sizeof layout);
    for (size_t at = 0; at + AES_BLOCK <= RESIDUE_BYTES; at++) {
        if (memcmp(&residue_copy[at], layout, AES_BLOCK) == 0) {
            return 1;
        }
    }
    return 0;
}

// The three sums of the last pass, as ghash_hw.c's hash_blocks adds them
// up: low, high and cross, each the sum over the pass's blocks of the
// products of a block's words and its power's words. The first block has
// the accumulator added, which is the accumulator after the passes before.
static void residue_sums(uint8_t powers[RESIDUE_POWERS][AES_BLOCK], uint64_t sums[3][2]) {
    size_t last = (size_t)(RESIDUE_PASSES - 1) * RESIDUE_POWERS * AES_BLOCK;
    uint8_t acc[AES_BLOCK];
    memcpy(acc, residue_acc, AES_BLOCK);
    ghash_hash_data_soft(acc, residue_subkey, residue_data, last);
    memset(sums, 0, sizeof(uint64_t[3][2]));
    for (size_t j = 0; j < RESIDUE_POWERS; j++) {
        uint8_t block[AES_BLOCK];
        memcpy(block, &residue_data[last + j * AES_BLOCK], AES_BLOCK);
        for (size_t i = 0; j == 0 && i < AES_BLOCK; i++) {
            block[i] = (uint8_t)(block[i] ^ acc[i]);
        }
        uint64_t x[2];
        uint64_t h[2];
        residue_words(block, x);
        residue_words(powers[RESIDUE_POWERS - 1 - j], h);
        residue_carryless_multiply(x[1], h[1], sums[0]);
        residue_carryless_multiply(x[0], h[0], sums[1]);
        residue_carryless_multiply(x[0], h[1], sums[2]);
        residue_carryless_multiply(x[1], h[0], sums[2]);
    }
}

static void run_residue(void) {
    rng_fill(residue_subkey, sizeof residue_subkey);
    rng_fill(residue_acc, sizeof residue_acc);
    rng_fill(residue_data, sizeof residue_data);
    residue_call();
    residue_snapshot();
    uint8_t powers[RESIDUE_POWERS][AES_BLOCK];
    memcpy(powers[0], residue_subkey, AES_BLOCK);
    for (size_t k = 1; k < RESIDUE_POWERS; k++) {
        memcpy(powers[k], powers[k - 1], AES_BLOCK);
        ghash_multiply_soft(powers[k], residue_subkey);
    }
    for (size_t k = 0; k < RESIDUE_POWERS; k++) {
        uint64_t words[2];
        residue_words(powers[k], words);
        if (residue_holds(words)) {
            char case_name[64];
            (void)snprintf(case_name, sizeof case_name, "data loop residue, H^%zu", k + 1);
            fail(case_name, "the stack below the call still holds this power of H");
            return;
        }
    }
    uint64_t sums[3][2];
    residue_sums(powers, sums);
    static const char *const names[3] = {"low", "high", "cross"};
    for (size_t i = 0; i < 3; i++) {
        if (residue_holds(sums[i])) {
            char case_name[64];
            (void)snprintf(case_name, sizeof case_name, "data loop residue, %s sum", names[i]);
            fail(case_name, "the stack below the call still holds the last pass's sum");
            return;
        }
    }
}

#endif
