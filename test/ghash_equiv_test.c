// GHASH on the carry-less multiply instruction (ghash_hw.c, AES=hw)
// against gcm.c's portable GHASH: same operands, same output, byte
// for byte. This is what holds the instruction path, because CBMC cannot
// read an intrinsic: the gcm and ghash harnesses in proof/
// cover the portable bodies, and this binary carries the instruction path
// to the same answers. test/aes_equiv_test.c does the same for the AES
// block cipher.
//
// Three levels are compared, from the narrowest up, so a divergence is
// named where it starts:
//
//   the multiply   gcm_multiply_by_subkey_hw against multiply_by_subkey
//   the data loop  gcm_hash_data_hw against hash_data, which adds the
//                  SP 800-38D §6.4 pad of a last block shorter than 16
//                  bytes
//   the AEAD       gcm_seal, gcm_open and gcm_ghash over the instruction
//                  GHASH against the same three over the portable one
//
// Both AEADs run aes_hw.c's block cipher, so GHASH is the only
// difference between them; test/aes_equiv_test.c holds that cipher to
// AES=soft.
//
// The multiply's operands are the edge cases first and then random
// pairs. The edge cases: zero; the field's one, which is x^0, the most
// significant bit of byte 0; x^127, the least significant bit of byte
// 15; all ones; and R, the constant SP 800-38D §6.3 adds on each
// reduction step, each against each. Then every pair of single-bit
// operands, whose product x^(i+j) runs every degree from 0 to 254, so
// every bit the reduction moves is set once on its own. Then the
// squaring shape acc == subkey, which ghash_hw.h admits.
//
// SP 800-38D and Wycheproof are not repeated here. bin/quic_test_hw and
// the Wycheproof AES=hw leg run the published vectors over the same
// AES=hw build, so the instruction path answers the standard directly
// rather than only through the portable one.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes_block.h"
#include "aes_public_key.h"
#include "ch_assert.h"
#include "gcm.h"
#include "ghash_hw.h"

// hkdf.c asserts its contracts, and aes.c links it for the Initial
// key constructor. Nothing here trips an assertion, so reaching this is
// a bug in the test.
noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ch_assert: %s at %s:%d\n", cond, file, line);
    exit(134);
}

// xorshift64 from a fixed seed, so an ordinary run replays the same
// inputs and a mismatch reproduces bit for bit. CH_GHASH_EQUIV_SEED
// replaces the seed, and the binary prints the seed it used. A value that
// is not a number, or zero, keeps the default: xorshift64 is all zeroes
// forever from zero.
#define GHASH_EQUIV_DEFAULT_SEED UINT64_C(0x9e3779b97f4a7c15)
static uint64_t rng_state = GHASH_EQUIV_DEFAULT_SEED;

static uint64_t rng_seed_from_env(void) {
    const char *text = getenv("CH_GHASH_EQUIV_SEED");
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

// The portable GHASH and the AEAD over it, compiled in under these names
// by test/ghash_equiv_soft.c. Declared here rather than in a header
// because the renaming is this binary's alone.
void ghash_multiply_soft(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK]);
void ghash_hash_data_soft(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK],
                          const uint8_t *data, size_t n);
void gcm_seal_soft(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
                   size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct, uint8_t tag[GCM_TAG]);
int gcm_open_soft(const aes_public_key *k, const uint8_t nonce[AES_IV], const uint8_t *aad,
                  size_t aad_len, const uint8_t *ct, size_t n, const uint8_t tag[GCM_TAG],
                  uint8_t *pt);
void gcm_ghash_soft(const aes_public_key *k, const uint8_t *aad, size_t aad_len, const uint8_t *ct,
                    size_t n, uint8_t out[AES_BLOCK]);

// The largest payload: one full TLS record (RFC 8446 §5.1), the most a
// SUITE=aesgcm record seals at once.
#define MAX_DATA 16384
#define MAX_AAD 64

static int failures = 0;
static unsigned long multiplies = 0;
static unsigned long loops = 0;
static unsigned long aeads = 0;

static void print_hex(const char *name, const uint8_t *p, size_t n) {
    (void)fprintf(stderr, "  %s ", name);
    for (size_t i = 0; i < n; i++) {
        (void)fprintf(stderr, "%02x", p[i]);
    }
    (void)fprintf(stderr, "\n");
}

static void fail(const char *case_name, const char *what) {
    failures++;
    (void)fprintf(stderr, "FAIL %s: %s\n", case_name, what);
}

// One multiply on both paths. The operands are printed on a mismatch so
// a failure is readable without a debugger.
static void compare_multiply(const char *case_name, const uint8_t acc[AES_BLOCK],
                             const uint8_t subkey[AES_BLOCK]) {
    uint8_t soft[AES_BLOCK];
    uint8_t hw[AES_BLOCK];
    memcpy(soft, acc, AES_BLOCK);
    memcpy(hw, acc, AES_BLOCK);
    ghash_multiply_soft(soft, subkey);
    gcm_multiply_by_subkey_hw(hw, subkey);
    if (memcmp(soft, hw, AES_BLOCK) != 0) {
        fail(case_name, "the multiplies differ");
        print_hex("acc   ", acc, AES_BLOCK);
        print_hex("subkey", subkey, AES_BLOCK);
        print_hex("soft  ", soft, AES_BLOCK);
        print_hex("hw    ", hw, AES_BLOCK);
        return;
    }
    multiplies++;
}

static void run_multiply_fixed(void) {
    static const uint8_t zero[AES_BLOCK] = {0};
    static const uint8_t one[AES_BLOCK] = {0x80};
    static const uint8_t x127[AES_BLOCK] = {[AES_BLOCK - 1] = 0x01};
    static const uint8_t ones[AES_BLOCK] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    static const uint8_t r[AES_BLOCK] = {0xe1};
    const uint8_t *values[5] = {zero, one, x127, ones, r};
    const char *names[5] = {"zero", "one", "x^127", "ones", "R"};
    for (size_t a = 0; a < 5; a++) {
        for (size_t h = 0; h < 5; h++) {
            char case_name[64];
            (void)snprintf(case_name, sizeof case_name, "multiply acc=%s subkey=%s", names[a],
                           names[h]);
            compare_multiply(case_name, values[a], values[h]);
        }
    }
}

// Bit i counted from the most significant bit of byte 0, which is the
// coefficient of x^i in SP 800-38D's bit order.
static void set_single_bit(uint8_t block[AES_BLOCK], size_t bit) {
    memset(block, 0, AES_BLOCK);
    block[bit / 8] = (uint8_t)(0x80U >> (bit % 8));
}

static void run_multiply_single_bits(void) {
    for (size_t i = 0; i < (size_t)8 * AES_BLOCK; i++) {
        for (size_t j = 0; j < (size_t)8 * AES_BLOCK; j++) {
            uint8_t acc[AES_BLOCK];
            uint8_t subkey[AES_BLOCK];
            set_single_bit(acc, i);
            set_single_bit(subkey, j);
            char case_name[64];
            (void)snprintf(case_name, sizeof case_name, "multiply x^%zu by x^%zu", i, j);
            compare_multiply(case_name, acc, subkey);
            if (failures > 0) {
                return; // one mismatch is the answer; the rest would repeat it
            }
        }
    }
}

// acc == subkey on both paths: the square of a random element.
static void run_multiply_squares(void) {
    for (unsigned long i = 0; i < 1000; i++) {
        uint8_t soft[AES_BLOCK];
        uint8_t hw[AES_BLOCK];
        rng_fill(soft, sizeof soft);
        memcpy(hw, soft, AES_BLOCK);
        ghash_multiply_soft(soft, soft);
        gcm_multiply_by_subkey_hw(hw, hw);
        if (memcmp(soft, hw, AES_BLOCK) != 0) {
            fail("multiply acc == subkey", "the squares differ");
            print_hex("soft", soft, AES_BLOCK);
            print_hex("hw  ", hw, AES_BLOCK);
            return;
        }
        multiplies++;
    }
}

// Random pairs. The count finds a divergence in any product word or
// reduction term with overwhelming probability and keeps this binary
// inside `make check`'s one-minute budget.
#define RANDOM_MULTIPLIES 100000

static void run_multiply_random(void) {
    for (unsigned long i = 0; i < RANDOM_MULTIPLIES; i++) {
        uint8_t acc[AES_BLOCK];
        uint8_t subkey[AES_BLOCK];
        rng_fill(acc, sizeof acc);
        rng_fill(subkey, sizeof subkey);
        char case_name[64];
        (void)snprintf(case_name, sizeof case_name, "multiply random pair %lu", i);
        compare_multiply(case_name, acc, subkey);
        if (failures > 0) {
            return;
        }
    }
}

static uint8_t data[MAX_DATA];

// One run of the data loop on both paths, from the same accumulator.
static void compare_hash_data(const char *case_name, const uint8_t *bytes, size_t n) {
    uint8_t acc[AES_BLOCK];
    uint8_t subkey[AES_BLOCK];
    rng_fill(acc, sizeof acc);
    rng_fill(subkey, sizeof subkey);
    uint8_t soft[AES_BLOCK];
    uint8_t hw[AES_BLOCK];
    memcpy(soft, acc, AES_BLOCK);
    memcpy(hw, acc, AES_BLOCK);
    ghash_hash_data_soft(soft, subkey, bytes, n);
    gcm_hash_data_hw(hw, subkey, bytes, n);
    if (memcmp(soft, hw, AES_BLOCK) != 0) {
        fail(case_name, "the data loops differ");
        print_hex("acc   ", acc, AES_BLOCK);
        print_hex("subkey", subkey, AES_BLOCK);
        print_hex("soft  ", soft, AES_BLOCK);
        print_hex("hw    ", hw, AES_BLOCK);
        return;
    }
    loops++;
}

// Every length from zero to four blocks and a byte, which puts each
// length of a last partial block through the pad, then random lengths up
// to MAX_DATA. NULL with a length of zero is the shape gcm.h admits
// for empty associated data.
static void run_hash_data(void) {
    compare_hash_data("data loop over NULL", NULL, 0);
    for (size_t n = 0; n <= 4 * AES_BLOCK + 1; n++) {
        rng_fill(data, n);
        char case_name[64];
        (void)snprintf(case_name, sizeof case_name, "data loop over %zu bytes", n);
        compare_hash_data(case_name, data, n);
    }
    for (unsigned long i = 0; i < 200; i++) {
        size_t n = (size_t)(rng_next() % (MAX_DATA + 1));
        rng_fill(data, n);
        char case_name[64];
        (void)snprintf(case_name, sizeof case_name, "data loop random %lu, %zu bytes", i, n);
        compare_hash_data(case_name, data, n);
        if (failures > 0) {
            return;
        }
    }
}

static uint8_t plaintext[MAX_DATA];
static uint8_t soft_ct[MAX_DATA];
static uint8_t hw_ct[MAX_DATA];
static uint8_t soft_pt[MAX_DATA];
static uint8_t hw_pt[MAX_DATA];

// The byte an open's output buffer holds before the call, so a refused
// open can be seen to have written nothing.
#define UNWRITTEN 0xa5

static int all_unwritten(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (p[i] != UNWRITTEN) {
            return 0;
        }
    }
    return 1;
}

// Opens the sealed bytes under both paths with the given tag and
// requires both to give the expected verdict. A genuine tag must open to
// the plaintext on both, and a wrong one must leave both output buffers
// unwritten.
static void compare_open(const char *case_name, const aes_public_key *k,
                         const uint8_t nonce[AES_IV], const uint8_t *aad, size_t aad_len, size_t n,
                         const uint8_t tag[GCM_TAG], int genuine) {
    memset(soft_pt, UNWRITTEN, n);
    memset(hw_pt, UNWRITTEN, n);
    int soft_ok = gcm_open_soft(k, nonce, aad, aad_len, hw_ct, n, tag, soft_pt);
    int hw_ok = gcm_open(k, nonce, aad, aad_len, hw_ct, n, tag, hw_pt);
    if (soft_ok != genuine || hw_ok != genuine) {
        fail(case_name, genuine ? "an open refused the genuine tag" : "an open took a wrong tag");
        return;
    }
    if (genuine && (memcmp(soft_pt, plaintext, n) != 0 || memcmp(hw_pt, plaintext, n) != 0)) {
        fail(case_name, "an open wrote bytes other than the plaintext");
    }
    if (!genuine && (!all_unwritten(soft_pt, n) || !all_unwritten(hw_pt, n))) {
        fail(case_name, "a refused open wrote to its output");
    }
}

// One AEAD case on both paths: seal, GHASH, open with the genuine tag and
// with one bit of it flipped, and the in-place seal quic_initial.c uses.
static void compare_aead(const char *case_name, size_t aad_len, size_t n) {
    uint8_t key[AES_128_KEY];
    uint8_t nonce[AES_IV];
    uint8_t aad[MAX_AAD];
    rng_fill(key, sizeof key);
    rng_fill(nonce, sizeof nonce);
    rng_fill(aad, aad_len);
    rng_fill(plaintext, n);
    // A key from any 16 bytes, built the way test/gcm_tests.h builds
    // one: the two constructors in aes.h take a connection ID or the
    // Retry key, and SP 800-38D admits any key.
    aes_public_key k;
    memset(&k, 0, sizeof k);
    aes_expand_round_keys(key, k.key.round_keys);

    uint8_t soft_tag[GCM_TAG];
    uint8_t hw_tag[GCM_TAG];
    gcm_seal_soft(&k, nonce, aad, aad_len, plaintext, n, soft_ct, soft_tag);
    gcm_seal(&k, nonce, aad, aad_len, plaintext, n, hw_ct, hw_tag);
    if (memcmp(soft_ct, hw_ct, n) != 0 || memcmp(soft_tag, hw_tag, GCM_TAG) != 0) {
        fail(case_name, "the seals differ");
        print_hex("soft tag", soft_tag, GCM_TAG);
        print_hex("hw tag  ", hw_tag, GCM_TAG);
        return;
    }

    uint8_t soft_hash[AES_BLOCK];
    uint8_t hw_hash[AES_BLOCK];
    gcm_ghash_soft(&k, aad, aad_len, hw_ct, n, soft_hash);
    gcm_ghash(&k, aad, aad_len, hw_ct, n, hw_hash);
    if (memcmp(soft_hash, hw_hash, AES_BLOCK) != 0) {
        fail(case_name, "the GHASH outputs differ");
        print_hex("soft", soft_hash, AES_BLOCK);
        print_hex("hw  ", hw_hash, AES_BLOCK);
        return;
    }

    compare_open(case_name, &k, nonce, aad, aad_len, n, hw_tag, 1);
    uint8_t wrong_tag[GCM_TAG];
    memcpy(wrong_tag, hw_tag, GCM_TAG);
    wrong_tag[rng_next() % GCM_TAG] ^= (uint8_t)(1U << (rng_next() % 8));
    compare_open(case_name, &k, nonce, aad, aad_len, n, wrong_tag, 0);

    memcpy(hw_pt, plaintext, n);
    uint8_t in_place_tag[GCM_TAG];
    gcm_seal(&k, nonce, aad, aad_len, hw_pt, n, hw_pt, in_place_tag);
    if (memcmp(hw_pt, hw_ct, n) != 0 || memcmp(in_place_tag, hw_tag, GCM_TAG) != 0) {
        fail(case_name, "the in-place seal differs from the seal into a second buffer");
        return;
    }
    aeads++;
}

// Every associated-data length from 0 to 40 against every payload length
// from 0 to 48, which covers each partial block on both arguments, then
// random lengths up to MAX_AAD and MAX_DATA.
static void run_aead(void) {
    for (size_t aad_len = 0; aad_len <= 40; aad_len++) {
        for (size_t n = 0; n <= 48; n++) {
            char case_name[64];
            (void)snprintf(case_name, sizeof case_name, "aead aad %zu, payload %zu", aad_len, n);
            compare_aead(case_name, aad_len, n);
            if (failures > 0) {
                return;
            }
        }
    }
    for (unsigned long i = 0; i < 100; i++) {
        size_t aad_len = (size_t)(rng_next() % (MAX_AAD + 1));
        size_t n = (size_t)(rng_next() % (MAX_DATA + 1));
        char case_name[64];
        (void)snprintf(case_name, sizeof case_name, "aead random %lu, aad %zu, payload %zu", i,
                       aad_len, n);
        compare_aead(case_name, aad_len, n);
        if (failures > 0) {
            return;
        }
    }
}

int main(void) {
    uint64_t seed = rng_seed_from_env();
    run_multiply_fixed();
    run_multiply_single_bits();
    run_multiply_squares();
    run_multiply_random();
    run_hash_data();
    run_aead();
    printf("ghash equivalence: %lu multiplies, %lu data loops and %lu AEAD cases agree "
           "between the portable GHASH and the carry-less multiply (seed 0x%llx)\n",
           multiplies, loops, aeads, (unsigned long long)seed);
    if (failures > 0) {
        printf("ghash equivalence: %d mismatches\n", failures);
        return 1;
    }
    return 0;
}
