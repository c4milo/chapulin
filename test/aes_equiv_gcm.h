// AES-GCM on the instructions under AES-128 and AES-256 round keys,
// against SP 800-38D computed one block at a time: counter mode on
// AES=soft and GHASH by §6.3's Algorithm 1, one bit at a time.
//
//   On x86-64, gcm_hw.h's seal and open passes, gcm_hw.c's and, on a CPU
//   with VAES and VPCLMULQDQ, gcm_vaes.c's. Each case compares the output
//   bytes, the counter afterwards and the accumulator. The cases take
//   every pass count from 1 to 4, and 128, a 16 KiB record's; counters
//   that carry out of byte 15 inside a pass, or wrap 2^32 to zero at each
//   place in a pass, where a carry into the twelve IV bytes would show;
//   and the layouts gcm.c passes: separate buffers and in == out for both,
//   and out five bytes below in for the open, as record.c's open writes.
//
//   On arm64, gcm_arm64.h's whole seal and open, gcm_arm64.c's and, on a
//   CPU with FEAT_SHA3, gcm_arm64_eor3.c's. Each case compares the output
//   bytes and the tag. The cases take every text length from 0 to 300
//   bytes, the lengths within a block and a byte of 1, 2, 3, 8, 16, 31 to 34
//   and 128 passes, associated data of 0 to 40 bytes and of 129, and the same
//   layouts.
//
// test/ghash_equiv_test.c holds the same entries to gcm.c's portable
// GHASH through whole AEADs under AES-128 alone. Included by
// test/aes_equiv_test.c only, after test/aes_equiv_counter.h, whose
// counter_start, counter_increment and layouts it uses.
#ifndef CH_AES_EQUIV_GCM_H
#define CH_AES_EQUIV_GCM_H

// test/hash_instructions_cpu.h asks the CPU only for a host object, which
// this binary is: test/aes_equiv_hw.c defines CH_CPU_RUNTIME for its unit.
#ifndef CH_CPU_RUNTIME
#define CH_CPU_RUNTIME 1
#endif
#include "hash_instructions_cpu.h"

#define GCM_PASS_BYTES ((size_t)8 * AES_BLOCK)
#define GCM_MAX_TEXT ((size_t)128 * GCM_PASS_BYTES + AES_BLOCK + 1)
#define GCM_MAX_AAD 129

static unsigned long gcm_cases = 0;

static uint8_t gcm_input[GCM_MAX_TEXT];
static uint8_t gcm_want[GCM_MAX_TEXT];
static uint8_t gcm_buffer[GCM_MAX_TEXT + COUNTER_SHIFT];
#ifdef __aarch64__
// The whole AEAD's associated data, which arm64 alone tests.
static uint8_t gcm_aad[GCM_MAX_AAD];
#endif

// x = x * h in GF(2^128), SP 800-38D §6.3's Algorithm 1 bit by bit. The
// branches read test data.
static void gcm_multiply(uint8_t x[AES_BLOCK], const uint8_t h[AES_BLOCK]) {
    uint8_t z[AES_BLOCK] = {0};
    uint8_t v[AES_BLOCK];
    memcpy(v, h, AES_BLOCK);
    for (size_t i = 0; i < (size_t)8 * AES_BLOCK; i++) {
        if ((x[i / 8] >> (7 - i % 8)) & 1U) {
            for (size_t j = 0; j < AES_BLOCK; j++) {
                z[j] ^= v[j];
            }
        }
        unsigned low = v[AES_BLOCK - 1] & 1U;
        for (size_t j = AES_BLOCK - 1; j > 0; j--) {
            v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1] << 7));
        }
        v[0] >>= 1;
        if (low) {
            v[0] ^= 0xe1;
        }
    }
    memcpy(x, z, AES_BLOCK);
}

// acc = GHASH from acc over n bytes, the last block padded with zeros.
static void gcm_hash(uint8_t acc[AES_BLOCK], const uint8_t h[AES_BLOCK], const uint8_t *data,
                     size_t n) {
    for (size_t at = 0; at < n; at += AES_BLOCK) {
        for (size_t j = 0; j < AES_BLOCK && at + j < n; j++) {
            acc[j] ^= data[at + j];
        }
        gcm_multiply(acc, h);
    }
}

// A fresh key, its soft and hardware round keys, and H under it.
static void gcm_key(int aes256, uint8_t soft_keys[], uint8_t hw_keys[], uint8_t h[AES_BLOCK]) {
    static const uint8_t zero[AES_BLOCK] = {0};
    uint8_t key[AES_256_KEY];
    rng_fill(key, sizeof key);
    if (aes256) {
        aes_expand_round_keys_256_soft(key, soft_keys);
        aes_expand_round_keys_256_hw(key, hw_keys);
        aes_cipher_block_256_soft(soft_keys, zero, h);
    } else {
        aes_expand_round_keys_soft(key, soft_keys);
        aes_expand_round_keys_hw(key, hw_keys);
        aes_cipher_block_soft(soft_keys, zero, h);
    }
}

// gcm_want = gcm_input exclusive-ored with the soft cipher of the blocks
// after counter, n bytes; counter advances past them.
static void gcm_counter_mode(int aes256, const uint8_t soft_keys[], uint8_t counter[AES_BLOCK],
                             size_t n) {
    for (size_t at = 0; at < n; at += AES_BLOCK) {
        uint8_t keystream[AES_BLOCK];
        counter_increment(counter);
        if (aes256) {
            aes_cipher_block_256_soft(soft_keys, counter, keystream);
        } else {
            aes_cipher_block_soft(soft_keys, counter, keystream);
        }
        for (size_t j = 0; j < AES_BLOCK && at + j < n; j++) {
            gcm_want[at + j] = (uint8_t)(gcm_input[at + j] ^ keystream[j]);
        }
    }
}

// The input and output a case's layout names: separate buffers, in ==
// out, or out COUNTER_SHIFT bytes below in, with the input copied in.
static const uint8_t *gcm_layout(enum counter_layout layout, size_t n, uint8_t **out) {
    *out = gcm_buffer;
    if (layout == COUNTER_IN_PLACE) {
        memcpy(gcm_buffer, gcm_input, n);
        return gcm_buffer;
    }
    if (layout == COUNTER_SHIFTED) {
        memcpy(gcm_buffer + COUNTER_SHIFT, gcm_input, n);
        return gcm_buffer + COUNTER_SHIFT;
    }
    return gcm_input;
}

static void gcm_fail(const char *name, const char *what, int aes256, size_t aad_len, size_t n,
                     enum counter_layout layout) {
    (void)fprintf(stderr, "FAIL %s: %s, AES-%d, aad %zu, text %zu, layout %d\n", name, what,
                  aes256 ? 256 : 128, aad_len, n, (int)layout);
    failures++;
}

#ifdef __x86_64__
// The passes entries, compiled by test/aes_equiv_hw.c and
// test/aes_equiv_vaes.c under CH_CPU_RUNTIME, which this binary's main
// does not define, so gcm_hw.h declares nothing here.
typedef void (*passes_entry)(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                             uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK],
                             const uint8_t *in, size_t passes, uint8_t *out);
void gcm_seal_passes_hw(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                        uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *in,
                        size_t passes, uint8_t *out);
void gcm_open_passes_hw(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                        uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *in,
                        size_t passes, uint8_t *out);
void gcm_seal_passes_vaes(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                          uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK],
                          const uint8_t *in, size_t passes, uint8_t *out);
void gcm_open_passes_vaes(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                          uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK],
                          const uint8_t *in, size_t passes, uint8_t *out);

// One passes case. seal says whether the entry is a seal, whose GHASH runs
// over its output, or an open, whose GHASH runs over its input.
static void compare_passes(const char *name, passes_entry entry, int seal, int aes256,
                           const uint8_t start[AES_BLOCK], size_t passes,
                           enum counter_layout layout) {
    size_t n = passes * GCM_PASS_BYTES;
    uint8_t soft_keys[ROUND_KEY_BYTES_256];
    uint8_t hw_keys[ROUND_KEY_BYTES_256];
    uint8_t h[AES_BLOCK];
    gcm_key(aes256, soft_keys, hw_keys, h);
    rng_fill(gcm_input, n);
    uint8_t acc_start[AES_BLOCK];
    rng_fill(acc_start, sizeof acc_start);
    uint8_t want_counter[AES_BLOCK];
    memcpy(want_counter, start, AES_BLOCK);
    gcm_counter_mode(aes256, soft_keys, want_counter, n);
    uint8_t want_acc[AES_BLOCK];
    memcpy(want_acc, acc_start, AES_BLOCK);
    gcm_hash(want_acc, h, seal ? gcm_want : gcm_input, n);

    uint8_t *out = NULL;
    const uint8_t *in = gcm_layout(layout, n, &out);
    uint8_t counter[AES_BLOCK];
    uint8_t acc[AES_BLOCK];
    memcpy(counter, start, AES_BLOCK);
    memcpy(acc, acc_start, AES_BLOCK);
    entry(hw_keys, aes256 ? AES_256_ROUNDS : AES_128_ROUNDS, counter, acc, h, in, passes, out);
    if (memcmp(out, gcm_want, n) != 0 || memcmp(counter, want_counter, AES_BLOCK) != 0 ||
        memcmp(acc, want_acc, AES_BLOCK) != 0) {
        gcm_fail(name, "output, counter or accumulator differs", aes256, 0, n, layout);
        print_hex("start", start, AES_BLOCK);
        return;
    }
    gcm_cases++;
}

static void run_passes_on(const char *name, passes_entry entry, int seal) {
    // The last four bytes of a start: low counts, a carry out of byte 15
    // inside the first pass, and 2^32 within two passes.
    static const uint32_t lows[] = {1U,
                                    0xf9U,
                                    0xfcU,
                                    0xffffU,
                                    UINT32_MAX - 15U,
                                    UINT32_MAX - 8U,
                                    UINT32_MAX - 7U,
                                    UINT32_MAX - 3U,
                                    UINT32_MAX};
    // A seal's GHASH runs over its output, so it takes no layout whose
    // output overlaps its input other than in == out (gcm_hw.h).
    int layouts = seal ? COUNTER_SHIFTED : COUNTER_LAYOUTS;
    uint8_t start[AES_BLOCK];
    for (int aes256 = 0; aes256 <= 1 && failures == 0; aes256++) {
        for (int layout = 0; layout < layouts; layout++) {
            for (size_t l = 0; l < sizeof lows / sizeof lows[0]; l++) {
                for (size_t passes = 1; passes <= 4; passes++) {
                    counter_start(start, lows[l]);
                    compare_passes(name, entry, seal, aes256, start, passes,
                                   (enum counter_layout)layout);
                }
            }
            counter_start(start, 1);
            compare_passes(name, entry, seal, aes256, start, 128, (enum counter_layout)layout);
        }
    }
}

static void run_gcm(void) {
    run_passes_on("gcm_seal_passes_hw", gcm_seal_passes_hw, 1);
    run_passes_on("gcm_open_passes_hw", gcm_open_passes_hw, 0);
    if (x86_cpu_has_vaes()) {
        run_passes_on("gcm_seal_passes_vaes", gcm_seal_passes_vaes, 1);
        run_passes_on("gcm_open_passes_vaes", gcm_open_passes_vaes, 0);
    }
}
#endif // __x86_64__

#ifdef __aarch64__
// The whole AEAD entries, compiled by test/aes_equiv_arm64.c and
// test/aes_equiv_arm64_eor3.c. A seal and an open take the same shape of
// arguments.
typedef void (*aead_entry)(const uint8_t *round_keys, size_t rounds, const uint8_t nonce[AES_IV],
                           const uint8_t *aad, size_t aad_len, const uint8_t *in, size_t n,
                           uint8_t *out, uint8_t tag[AES_BLOCK]);
void gcm_seal_arm64(const uint8_t *round_keys, size_t rounds, const uint8_t nonce[AES_IV],
                    const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                    uint8_t tag[AES_BLOCK]);
void gcm_open_arm64(const uint8_t *round_keys, size_t rounds, const uint8_t nonce[AES_IV],
                    const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n, uint8_t *pt,
                    uint8_t want[AES_BLOCK]);
void gcm_seal_arm64_eor3(const uint8_t *round_keys, size_t rounds, const uint8_t nonce[AES_IV],
                         const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t n,
                         uint8_t *ct, uint8_t tag[AES_BLOCK]);
void gcm_open_arm64_eor3(const uint8_t *round_keys, size_t rounds, const uint8_t nonce[AES_IV],
                         const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n,
                         uint8_t *pt, uint8_t want[AES_BLOCK]);

// One case: a fresh key, nonce, associated data and text; the reference
// seal; then the seal in the layout named, compared with it; then the
// open of the reference ciphertext in the same layout, which must return
// the text and the tag.
static void compare_aead(const char *name, aead_entry seal, aead_entry open, int aes256,
                         size_t aad_len, size_t n, enum counter_layout layout) {
    uint8_t soft_keys[ROUND_KEY_BYTES_256];
    uint8_t hw_keys[ROUND_KEY_BYTES_256];
    uint8_t h[AES_BLOCK];
    gcm_key(aes256, soft_keys, hw_keys, h);
    size_t rounds = aes256 ? AES_256_ROUNDS : AES_128_ROUNDS;
    uint8_t nonce[AES_IV];
    rng_fill(nonce, sizeof nonce);
    rng_fill(gcm_aad, aad_len);
    rng_fill(gcm_input, n);

    // The reference: J0 = nonce || 1, counter mode from J0, GHASH over the
    // associated data, the ciphertext and the lengths, and the tag.
    uint8_t first[AES_BLOCK] = {0};
    memcpy(first, nonce, AES_IV);
    first[AES_BLOCK - 1] = 1;
    uint8_t counter[AES_BLOCK];
    memcpy(counter, first, AES_BLOCK);
    gcm_counter_mode(aes256, soft_keys, counter, n);
    uint8_t want_tag[AES_BLOCK] = {0};
    gcm_hash(want_tag, h, gcm_aad, aad_len);
    gcm_hash(want_tag, h, gcm_want, n);
    uint8_t lengths[AES_BLOCK] = {0};
    const uint64_t bits[2] = {(uint64_t)aad_len * 8U, (uint64_t)n * 8U};
    for (size_t i = 0; i < AES_BLOCK; i++) {
        lengths[i] = (uint8_t)(bits[i / 8] >> (8 * (7 - i % 8)));
    }
    gcm_hash(want_tag, h, lengths, AES_BLOCK);
    uint8_t mask[AES_BLOCK];
    if (aes256) {
        aes_cipher_block_256_soft(soft_keys, first, mask);
    } else {
        aes_cipher_block_soft(soft_keys, first, mask);
    }
    for (size_t i = 0; i < AES_BLOCK; i++) {
        want_tag[i] ^= mask[i];
    }

    uint8_t tag[AES_BLOCK];
    uint8_t *out = NULL;
    if (layout != COUNTER_SHIFTED) {
        const uint8_t *in = gcm_layout(layout, n, &out);
        seal(hw_keys, rounds, nonce, gcm_aad, aad_len, in, n, out, tag);
        if (memcmp(out, gcm_want, n) != 0 || memcmp(tag, want_tag, AES_BLOCK) != 0) {
            gcm_fail(name, "the seal differs", aes256, aad_len, n, layout);
            return;
        }
    }
    // The open reads the reference ciphertext, so the plaintext it writes
    // is the case's input.
    memcpy(gcm_input, gcm_want, n);
    rng_fill(gcm_want, n);
    const uint8_t *in = gcm_layout(layout, n, &out);
    open(hw_keys, rounds, nonce, gcm_aad, aad_len, in, n, out, tag);
    // The plaintext is the case's first input: counter mode twice.
    memcpy(counter, first, AES_BLOCK);
    gcm_counter_mode(aes256, soft_keys, counter, n);
    if (memcmp(out, gcm_want, n) != 0 || memcmp(tag, want_tag, AES_BLOCK) != 0) {
        gcm_fail(name, "the open differs", aes256, aad_len, n, layout);
        return;
    }
    gcm_cases++;
}

// Every case for one key size and one layout.
static void run_aead_cases(const char *name, aead_entry seal, aead_entry open, int aes256,
                           enum counter_layout layout) {
    static const size_t aad_lengths[] = {5, 13, 21};
    static const size_t pass_counts[] = {1, 2, 3, 8, 16, 31, 32, 33, 34, 128};
    for (size_t n = 0; n <= 300 && failures == 0; n++) {
        compare_aead(name, seal, open, aes256, aad_lengths[n % 3], n, layout);
    }
    for (size_t p = 0; p < sizeof pass_counts / sizeof pass_counts[0] && failures == 0; p++) {
        for (size_t d = 0; d <= 2 * AES_BLOCK + 2; d++) {
            size_t n = pass_counts[p] * GCM_PASS_BYTES + d - (AES_BLOCK + 1);
            compare_aead(name, seal, open, aes256, 5, n, layout);
        }
    }
    for (size_t aad_len = 0; aad_len <= 40 && failures == 0; aad_len++) {
        compare_aead(name, seal, open, aes256, aad_len, 3 * GCM_PASS_BYTES + 7, layout);
    }
    compare_aead(name, seal, open, aes256, GCM_MAX_AAD, 2 * GCM_PASS_BYTES, layout);
}

static void run_aead_on(const char *name, aead_entry seal, aead_entry open) {
    for (int aes256 = 0; aes256 <= 1 && failures == 0; aes256++) {
        for (int layout = 0; layout < COUNTER_LAYOUTS && failures == 0; layout++) {
            run_aead_cases(name, seal, open, aes256, (enum counter_layout)layout);
        }
    }
}

// Every case on gcm_arm64.c's entries, then on gcm_arm64_eor3.c's where
// this CPU has FEAT_SHA3. Under CH_REQUIRE_HASH_INSTRUCTIONS a CPU without
// it counts as a failure.
static void run_gcm(void) {
    run_aead_on("gcm_arm64", gcm_seal_arm64, gcm_open_arm64);
    if (cpu_has_sha3_instructions()) {
        run_aead_on("gcm_arm64_eor3", gcm_seal_arm64_eor3, gcm_open_arm64_eor3);
    } else if (hash_instructions_required()) {
        (void)fprintf(stderr, "aes equivalence: this CPU lacks FEAT_SHA3, and "
                              "CH_REQUIRE_HASH_INSTRUCTIONS is 1\n");
        failures++;
    } else {
        printf("aes equivalence: SKIP gcm_arm64_eor3: this CPU lacks FEAT_SHA3\n");
    }
}
#endif // __aarch64__

#endif
