// AES=hw against AES=soft: same key, same input, same output, byte for
// byte, for AES-128 and for AES-256. This is what holds the hardware
// path, because CBMC cannot read an intrinsic — an AES instruction has no
// C body to unwind, so proof/aes_harness.c and
// proof/aes256_harness.c prove quic_aes_soft.c and this binary
// carries aes_hw.c to the same answer. The AES-256 half is what holds
// TLS_AES_256_GCM_SHA384's cipher: a library object runs that one on the
// instructions alone, and the software reference exists for this binary
// and the proof.
//
// Two things are compared, not one. The round keys
// aes_expand_round_keys writes are compared whole, so a key schedule that
// diverges is named at the schedule rather than three rounds later inside
// a block; and the block aes_cipher_block writes is compared, which is
// the answer callers depend on.
//
// The inputs are the edge cases first and then random pairs. The edge
// cases are the ones a table and an instruction are most likely to
// disagree about: all-zero and all-ones operands, every single-bit key,
// every single-bit block, and the byte-counting patterns. Random pairs
// follow, from the seeded generator below, so an ordinary run replays
// exactly and the nightly can vary CH_AES_EQUIV_SEED.
//
// FIPS 197 and RFC 9001 Appendix A are not repeated here. bin/quic_test
// holds those vectors and bin/quic_test_hw runs the same binary built
// AES=hw, so both implementations answer the published standards
// directly rather than only through each other. docs/quic.md, "What the
// AES axis proves", states the division.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes_block.h"

// xorshift64, the generator test/diff_driver.h uses, written here
// because that header also carries the pipe protocol to the Lean spec
// process and this binary talks to no oracle. The default seed is fixed,
// so an ordinary run replays the same pairs and a mismatch reproduces
// bit for bit; the nightly sets CH_AES_EQUIV_SEED to a different value
// and this binary prints the seed it used. Never seed from time(): a
// seed nobody recorded is a failure nobody can reproduce.
#define AES_EQUIV_DEFAULT_SEED UINT64_C(0x9e3779b97f4a7c15)
static uint64_t rng_state = AES_EQUIV_DEFAULT_SEED;

// Reads CH_AES_EQUIV_SEED, if set, as the seed, and returns the seed in
// use so the caller can print it. A value that is not a number, or zero,
// keeps the default: xorshift64 is all zeroes forever from zero.
static uint64_t rng_seed_from_env(void) {
    const char *text = getenv("CH_AES_EQUIV_SEED");
    if (text != NULL) {
        char *end = NULL;
        unsigned long long value = strtoull(text, &end, 0);
        if (end != text && *end == 0 && value != 0) {
            rng_state = (uint64_t)value;
        }
    }
    return rng_state;
}

static uint64_t rng_next(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

static void rng_fill(uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)(rng_next() >> 56);
    }
}

// The two implementations, each compiled under its own name by
// test/aes_equiv_soft.c and test/aes_equiv_hw.c. Declared here rather
// than in a header because the renaming is this binary's alone.
#define ROUND_KEY_BYTES ((size_t)AES_ROUND_KEYS * AES_BLOCK)
#define ROUND_KEY_BYTES_256 ((size_t)AES_256_ROUND_KEYS * AES_BLOCK)

void aes_expand_round_keys_soft(const uint8_t key[AES_128_KEY], uint8_t round_keys[]);
void aes_cipher_block_soft(const uint8_t round_keys[], const uint8_t in[AES_BLOCK],
                           uint8_t out[AES_BLOCK]);
void aes_expand_round_keys_hw(const uint8_t key[AES_128_KEY], uint8_t round_keys[]);
void aes_cipher_block_hw(const uint8_t round_keys[], const uint8_t in[AES_BLOCK],
                         uint8_t out[AES_BLOCK]);
void aes_expand_round_keys_256_soft(const uint8_t key[AES_256_KEY], uint8_t round_keys[]);
void aes_cipher_block_256_soft(const uint8_t round_keys[], const uint8_t in[AES_BLOCK],
                               uint8_t out[AES_BLOCK]);
void aes_expand_round_keys_256_hw(const uint8_t key[AES_256_KEY], uint8_t round_keys[]);
void aes_cipher_block_256_hw(const uint8_t round_keys[], const uint8_t in[AES_BLOCK],
                             uint8_t out[AES_BLOCK]);

static int failures = 0;
static unsigned long compared = 0;
static unsigned long compared_256 = 0;

static void print_hex(const char *name, const uint8_t *p, size_t n) {
    (void)fprintf(stderr, "  %s ", name);
    for (size_t i = 0; i < n; i++) {
        (void)fprintf(stderr, "%02x", p[i]);
    }
    (void)fprintf(stderr, "\n");
}

// One pair: expand both schedules, compare them, encrypt under both,
// compare the blocks. The case name says which input produced a
// mismatch, and the bytes are printed so a failure is readable without
// a debugger.
static void compare(const char *case_name, const uint8_t key[AES_128_KEY],
                    const uint8_t block[AES_BLOCK]) {
    uint8_t soft_keys[ROUND_KEY_BYTES];
    uint8_t hw_keys[ROUND_KEY_BYTES];
    aes_expand_round_keys_soft(key, soft_keys);
    aes_expand_round_keys_hw(key, hw_keys);
    if (memcmp(soft_keys, hw_keys, ROUND_KEY_BYTES) != 0) {
        failures++;
        (void)fprintf(stderr, "FAIL %s: the key schedules differ\n", case_name);
        print_hex("key ", key, AES_128_KEY);
        print_hex("soft", soft_keys, ROUND_KEY_BYTES);
        print_hex("hw  ", hw_keys, ROUND_KEY_BYTES);
        return;
    }

    uint8_t soft_out[AES_BLOCK];
    uint8_t hw_out[AES_BLOCK];
    aes_cipher_block_soft(soft_keys, block, soft_out);
    aes_cipher_block_hw(hw_keys, block, hw_out);
    if (memcmp(soft_out, hw_out, AES_BLOCK) != 0) {
        failures++;
        (void)fprintf(stderr, "FAIL %s: the cipher blocks differ\n", case_name);
        print_hex("key ", key, AES_128_KEY);
        print_hex("in  ", block, AES_BLOCK);
        print_hex("soft", soft_out, AES_BLOCK);
        print_hex("hw  ", hw_out, AES_BLOCK);
        return;
    }

    // aes_block.h promises in == out works, and gcm.c relies
    // on it for the counter block. Both implementations run it here, and
    // each must land on the answer it just gave with distinct buffers.
    uint8_t soft_same[AES_BLOCK];
    uint8_t hw_same[AES_BLOCK];
    memcpy(soft_same, block, AES_BLOCK);
    memcpy(hw_same, block, AES_BLOCK);
    aes_cipher_block_soft(soft_keys, soft_same, soft_same);
    aes_cipher_block_hw(hw_keys, hw_same, hw_same);
    if (memcmp(soft_same, soft_out, AES_BLOCK) != 0 || memcmp(hw_same, hw_out, AES_BLOCK) != 0) {
        failures++;
        (void)fprintf(stderr, "FAIL %s: in == out differs from distinct buffers\n", case_name);
        print_hex("soft", soft_same, AES_BLOCK);
        print_hex("hw  ", hw_same, AES_BLOCK);
        return;
    }
    compared++;
}

// The AES-256 twin of compare above: the same three questions, over the
// fifteen round keys and fourteen rounds of Nk = 8.
static void compare_256(const char *case_name, const uint8_t key[AES_256_KEY],
                        const uint8_t block[AES_BLOCK]) {
    uint8_t soft_keys[ROUND_KEY_BYTES_256];
    uint8_t hw_keys[ROUND_KEY_BYTES_256];
    aes_expand_round_keys_256_soft(key, soft_keys);
    aes_expand_round_keys_256_hw(key, hw_keys);
    if (memcmp(soft_keys, hw_keys, ROUND_KEY_BYTES_256) != 0) {
        failures++;
        (void)fprintf(stderr, "FAIL %s: the AES-256 key schedules differ\n", case_name);
        print_hex("key ", key, AES_256_KEY);
        print_hex("soft", soft_keys, ROUND_KEY_BYTES_256);
        print_hex("hw  ", hw_keys, ROUND_KEY_BYTES_256);
        return;
    }
    uint8_t soft_out[AES_BLOCK];
    uint8_t hw_out[AES_BLOCK];
    aes_cipher_block_256_soft(soft_keys, block, soft_out);
    aes_cipher_block_256_hw(hw_keys, block, hw_out);
    if (memcmp(soft_out, hw_out, AES_BLOCK) != 0) {
        failures++;
        (void)fprintf(stderr, "FAIL %s: the AES-256 cipher blocks differ\n", case_name);
        print_hex("key ", key, AES_256_KEY);
        print_hex("in  ", block, AES_BLOCK);
        print_hex("soft", soft_out, AES_BLOCK);
        print_hex("hw  ", hw_out, AES_BLOCK);
        return;
    }
    uint8_t soft_same[AES_BLOCK];
    uint8_t hw_same[AES_BLOCK];
    memcpy(soft_same, block, AES_BLOCK);
    memcpy(hw_same, block, AES_BLOCK);
    aes_cipher_block_256_soft(soft_keys, soft_same, soft_same);
    aes_cipher_block_256_hw(hw_keys, hw_same, hw_same);
    if (memcmp(soft_same, soft_out, AES_BLOCK) != 0 || memcmp(hw_same, hw_out, AES_BLOCK) != 0) {
        failures++;
        (void)fprintf(stderr, "FAIL %s: AES-256 in == out differs from distinct buffers\n",
                      case_name);
        return;
    }
    compared_256++;
}

// The fixed operands a table and an instruction are most likely to
// disagree about: an all-zero and an all-ones key and block in every
// combination, and the byte-counting patterns FIPS 197's own vectors
// use.
static void run_fixed(void) {
    static const uint8_t zero[AES_BLOCK] = {0};
    static const uint8_t ones[AES_BLOCK] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t counting[AES_BLOCK];
    uint8_t descending[AES_BLOCK];
    for (size_t i = 0; i < AES_BLOCK; i++) {
        counting[i] = (uint8_t)i;
        descending[i] = (uint8_t)(0xff - i);
    }
    const uint8_t *values[4] = {zero, ones, counting, descending};
    const char *names[4] = {"zero", "ones", "counting", "descending"};
    for (size_t k = 0; k < 4; k++) {
        for (size_t b = 0; b < 4; b++) {
            char case_name[64];
            (void)snprintf(case_name, sizeof case_name, "fixed key=%s block=%s", names[k],
                           names[b]);
            compare(case_name, values[k], values[b]);
        }
    }
}

// Every single-bit key against a zero block, and every single-bit block
// against a zero key. A key schedule that drops or misplaces one bit
// shows here and nowhere in a random sample.
static void run_single_bits(void) {
    for (size_t bit = 0; bit < (size_t)8 * AES_128_KEY; bit++) {
        uint8_t key[AES_128_KEY] = {0};
        uint8_t block[AES_BLOCK] = {0};
        key[bit / 8] = (uint8_t)(1U << (bit % 8));
        char case_name[64];
        (void)snprintf(case_name, sizeof case_name, "single key bit %zu", bit);
        compare(case_name, key, block);

        uint8_t zero_key[AES_128_KEY] = {0};
        memset(block, 0, sizeof block);
        block[bit / 8] = (uint8_t)(1U << (bit % 8));
        (void)snprintf(case_name, sizeof case_name, "single block bit %zu", bit);
        compare(case_name, zero_key, block);
    }
}

// Random pairs from the seeded generator. The count is large enough that
// a divergence in any one round, byte or S-box entry is found with
// overwhelming probability, and small enough that this binary stays
// inside `make check`'s one-minute budget.
#define RANDOM_PAIRS 200000

static void run_random(void) {
    for (unsigned long i = 0; i < RANDOM_PAIRS; i++) {
        uint8_t key[AES_128_KEY];
        uint8_t block[AES_BLOCK];
        rng_fill(key, sizeof key);
        rng_fill(block, sizeof block);
        char case_name[64];
        (void)snprintf(case_name, sizeof case_name, "random pair %lu", i);
        compare(case_name, key, block);
        if (failures > 0) {
            return; // one mismatch is the answer; the rest would repeat it
        }
    }
}

// AES-256's fixed operands, single bits and random pairs, the three
// passes above over a 32-byte key. Every key bit is flipped on its own
// because Nk = 8 takes the second half of the key through a SubWord step
// AES-128 does not have, and a schedule that got that step wrong differs
// only for keys whose second half matters.
static void run_aes256(void) {
    uint8_t key[AES_256_KEY];
    uint8_t block[AES_BLOCK];
    static const uint8_t patterns[4] = {0x00, 0xff, 0x5a, 0xa5};
    for (size_t k = 0; k < sizeof patterns; k++) {
        for (size_t b = 0; b < sizeof patterns; b++) {
            memset(key, patterns[k], sizeof key);
            memset(block, patterns[b], sizeof block);
            compare_256("aes-256 fixed pattern", key, block);
        }
    }
    for (size_t bit = 0; bit < (size_t)8 * AES_256_KEY; bit++) {
        memset(key, 0, sizeof key);
        memset(block, 0, sizeof block);
        key[bit / 8] = (uint8_t)(1U << (bit % 8));
        compare_256("aes-256 single key bit", key, block);
    }
    for (size_t bit = 0; bit < (size_t)8 * AES_BLOCK; bit++) {
        memset(key, 0, sizeof key);
        memset(block, 0, sizeof block);
        block[bit / 8] = (uint8_t)(1U << (bit % 8));
        compare_256("aes-256 single block bit", key, block);
    }
    for (unsigned long i = 0; i < RANDOM_PAIRS && failures == 0; i++) {
        rng_fill(key, sizeof key);
        rng_fill(block, sizeof block);
        compare_256("aes-256 random pair", key, block);
    }
}

int main(void) {
    uint64_t seed = rng_seed_from_env();
    run_fixed();
    run_single_bits();
    run_random();
    run_aes256();
    printf("aes equivalence: %lu AES-128 pairs and %lu AES-256 pairs agree between AES=soft "
           "and AES=hw (seed 0x%llx)\n",
           compared, compared_256, (unsigned long long)seed);
    if (failures > 0) {
        printf("aes equivalence: %d mismatches\n", failures);
        return 1;
    }
    return 0;
}
