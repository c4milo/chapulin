// What gcm_hash_data_hw leaves on the stack. ghash_hw.c computes the
// powers of the hash subkey it needs, keeps them in its ghash_state on
// its frame beside the subkey and the sums each pass adds up, and wipes
// that state once when the call ends. The frame is dead after the
// return, but its bytes stay in memory below this binary's own frames
// until another call writes over them.
//
// residue_call makes one call over three passes of data, residue_snapshot
// copies the stack below its caller as deep as RESIDUE_BYTES, where the
// dead frame lay, and run_residue looks in the copy for three things, in
// the layout ghash_hw.c's vector registers hold them: bits 0 to 63 of the
// 128-bit value SP 800-38D's bytes read big-endian, then bits 64 to 127,
// each in the host's byte order:
//
//   H, and each power of it the call computed times x^-1, which is what
//   ghash_state holds;
//   the two halves of each such power added together, the operand of the
//   middle product, which ghash_hw.c computes in a register and never
//   stores, as one 64-bit word, so a copy the compiler left in a stack slot
//   of its own is found;
//   the three sums the last pass leaves in ghash_state, the carry-less
//   products of its blocks and the powers before the reduction.
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

// x^-1 in SP 800-38D's bytes: x^127 + x^6 + x + 1, the element ghash_hw.c
// multiplies H by.
static const uint8_t residue_inverse_x[AES_BLOCK] = {0xc2, [AES_BLOCK - 1] = 0x01};

// The two 64-bit words of a block SP 800-38D writes as 16 big-endian
// bytes, in the order ghash_hw.c's registers hold them: words[0] reads
// bytes 8 to 15, bits 0 to 63, and words[1] bytes 0 to 7.
static void residue_words(const uint8_t block[AES_BLOCK], uint64_t words[2]) {
    words[0] = 0;
    words[1] = 0;
    for (size_t i = 0; i < 8; i++) {
        words[1] = (words[1] << 8) | block[i];
        words[0] = (words[0] << 8) | block[8 + i];
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

// Whether the copy holds the n bytes of words in memory.
static int residue_holds(const uint64_t *words, size_t n) {
    uint8_t layout[AES_BLOCK];
    memcpy(layout, words, n);
    for (size_t at = 0; at + n <= RESIDUE_BYTES; at++) {
        if (memcmp(&residue_copy[at], layout, n) == 0) {
            return 1;
        }
    }
    return 0;
}

// The three sums of the last pass, as ghash_hw.c adds them up: low, high
// and middle, each the sum over the pass's blocks of a product of a
// block's words and its power's words. The first block has the
// accumulator added, which is the accumulator after the passes before.
// powers holds two words for each power, H^(k + 1) * x^-1 at 2 * k.
static void residue_sums(const uint64_t *powers, uint64_t sums[3][2]) {
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
        residue_words(block, x);
        const uint64_t *h = &powers[2 * (RESIDUE_POWERS - 1 - j)];
        residue_carryless_multiply(x[0], h[0], sums[0]);
        residue_carryless_multiply(x[1], h[1], sums[1]);
        residue_carryless_multiply(x[0] ^ x[1], h[0] ^ h[1], sums[2]);
    }
}

static int residue_found(const char *what, size_t index, const uint64_t *words, size_t n) {
    if (!residue_holds(words, n)) {
        return 0;
    }
    char case_name[64];
    (void)snprintf(case_name, sizeof case_name, "data loop residue, %s %zu", what, index);
    fail(case_name, "the stack below the call still holds this value");
    return 1;
}

static void run_residue(void) {
    rng_fill(residue_subkey, sizeof residue_subkey);
    rng_fill(residue_acc, sizeof residue_acc);
    rng_fill(residue_data, sizeof residue_data);
    residue_call();
    residue_snapshot();
    uint64_t subkey[2];
    residue_words(residue_subkey, subkey);
    if (residue_found("H", 1, subkey, AES_BLOCK)) {
        return;
    }
    // The two words of H^(k + 1) * x^-1 at 2 * k, and halves their sum.
    uint64_t powers[2 * RESIDUE_POWERS];
    uint8_t power[AES_BLOCK];
    memcpy(power, residue_subkey, AES_BLOCK);
    for (size_t k = 0; k < RESIDUE_POWERS; k++) {
        if (k > 0) {
            ghash_multiply_soft(power, residue_subkey);
        }
        uint8_t twisted[AES_BLOCK];
        memcpy(twisted, power, AES_BLOCK);
        ghash_multiply_soft(twisted, residue_inverse_x);
        uint64_t *words = &powers[2 * k];
        residue_words(twisted, words);
        uint64_t halves = words[0] ^ words[1];
        if (residue_found("power of H times x^-1, H^", k + 1, words, AES_BLOCK) ||
            residue_found("power's halves added, H^", k + 1, &halves, sizeof halves)) {
            return;
        }
    }
    uint64_t sums[3][2];
    residue_sums(powers, sums);
    static const char *const names[3] = {"low sum", "high sum", "middle sum"};
    for (size_t i = 0; i < 3; i++) {
        if (residue_found(names[i], RESIDUE_PASSES, sums[i], AES_BLOCK)) {
            return;
        }
    }
}

#endif
