#include "chacha20_avx512.h"

// The whole file compiles only in a host object on x86-64, or in a test
// unit over the lane model (chacha20_avx512.h).
#if (defined(CH_CPU_RUNTIME) && defined(__x86_64__)) || defined(CH_CHACHA20_AVX512_MODEL)

#include "avx512_wipe.h"
#include "ct.h"

// Every function from here to the pop at the end of this file carries the
// target attribute that turns AVX-512F on, and no function outside it does,
// as in chacha20_avx2.c. clang applies it through one attribute push; gcc's
// target pragma sets it for each function defined after it, until the pop.
// The object is compiled with no instruction flag, so only these functions
// hold AVX-512 instructions, and chacha20.c calls them only where the
// caller's CH_CPU_AVX512_IFMA bit says the CPU has AVX-512F. A unit that
// defines CH_CHACHA20_AVX512_MODEL compiles the same text over the lane
// model in portable C (chacha20_avx512_lanes.h) and pushes no target.
#ifndef CH_CHACHA20_AVX512_MODEL
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx512f"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx512f")
#endif
#endif

#include "chacha20_avx512_lanes.h"

// One pass: the sixteen blocks whose counters start at counter, their ten
// double rounds, and their keystream XORed into each whole block of
// out[0..limit), for a limit of 1 to PASS_BYTES. Returns the keystream of
// the block the limit ends inside, whose first limit % 64 bytes the caller
// XORs when limit % 64 is not 0.
static chacha_lanes pass(const uint32_t words[16], uint32_t counter, const uint8_t *in,
                         uint8_t *out, size_t limit) {
    chacha_lanes x[16];
    pass_input(x, words, counter);
    for (int i = 0; i < 10; i++) {
        double_round(x);
    }
    pass_keystream(x, words, counter);
    return xor_blocks(in, out, x, limit);
}

// The whole passes of n bytes. Returns the bytes left, below PASS_BYTES,
// and moves counter, in and out past the passes it ran.
static size_t whole_passes(const uint32_t words[16], uint32_t *counter, const uint8_t **in,
                           uint8_t **out, size_t n) {
    while (n >= PASS_BYTES) {
        (void)pass(words, *counter, *in, *out, PASS_BYTES);
        *counter += PASS_BLOCKS;
        *in += PASS_BYTES;
        *out += PASS_BYTES;
        n -= PASS_BYTES;
    }
    return n;
}

// The last 1 to PASS_BYTES - 1 bytes of a message on a pass of sixteen
// blocks: the whole blocks in the pass, and the last 1 to 63 bytes, when
// there are any, one at a time, as chacha20.c XORs its last block.
static void last_pass(const uint32_t words[16], uint32_t counter, const uint8_t *in, uint8_t *out,
                      size_t n) {
    chacha_lanes last = pass(words, counter, in, out, n);
    size_t whole = n - n % CHACHA20_BLOCK;
    if (whole < n) {
        xor_partial(in + whole, out + whole, last, n - whole);
    }
}

// A message of 1 to ROW_PASS_BYTES bytes: one row pass.
static void row_pass(const uint32_t words[16], uint32_t counter, const uint8_t *in, uint8_t *out,
                     size_t n) {
    chacha_lanes y[4];
    rows_input(y, words, counter);
    for (int i = 0; i < 10; i++) {
        double_round_rows(y);
    }
    rows_keystream(y, words, counter);
    xor_rows(in, out, y, n);
}

// The last whole pass of sixteen blocks and the 1 to ROW_PASS_BYTES bytes
// after it, in one loop: the sixteen lanes' rounds and the row pass's
// rounds do not depend on each other, so the CPU runs the second while the
// first waits on its own results. The pass's 1,024 bytes are written before
// the rest is read, so out <= in stays safe.
static void pass_with_rows(const uint32_t words[16], uint32_t counter, const uint8_t *in,
                           uint8_t *out, size_t rest) {
    chacha_lanes x[16];
    chacha_lanes y[4];
    pass_input(x, words, counter);
    rows_input(y, words, counter + PASS_BLOCKS);
    for (int i = 0; i < 10; i++) {
        double_round(x);
        double_round_rows(y);
    }
    pass_keystream(x, words, counter);
    (void)xor_blocks(in, out, x, PASS_BYTES);
    rows_keystream(y, words, counter + PASS_BLOCKS);
    xor_rows(in + PASS_BYTES, out + PASS_BYTES, y, rest);
}

// The n bytes: whole passes of sixteen blocks, and a last pass of sixteen
// for a rest above ROW_PASS_BYTES, or a row pass for a rest of 1 to
// ROW_PASS_BYTES, beside the last whole pass where there is one.
static void xor_passes(const uint32_t words[16], uint32_t counter, const uint8_t *in, uint8_t *out,
                       size_t n) {
    size_t rest = n % PASS_BYTES;
    if (rest == 0 || rest > ROW_PASS_BYTES) {
        n = whole_passes(words, &counter, &in, &out, n);
        if (n > 0) {
            last_pass(words, counter, in, out, n);
        }
        return;
    }
    if (n < PASS_BYTES) {
        row_pass(words, counter, in, out, n);
        return;
    }
    // Every whole pass but the last, then the last beside the rest.
    (void)whole_passes(words, &counter, &in, &out, n - PASS_BYTES - rest);
    pass_with_rows(words, counter, in, out, rest);
}

void chacha20_avx512_xor(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                         uint32_t counter, const uint8_t *in, uint8_t *out, size_t n) {
    uint32_t words[16];
    setup(words, key, nonce);
    xor_passes(words, counter, in, out, n);
    // The input words hold the key side by side, and aead_avx512.c's open
    // runs its last bytes here, so they are wiped (docs/decisions.md 226).
    ct_wipe(words, sizeof words);
    // The key, the state and the keystream passed through the vector
    // registers, and the compiler clears none of them on return.
    chacha_lanes_wipe_registers();
}

#ifndef CH_CHACHA20_AVX512_MODEL
#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif
#endif

#endif // (CH_CPU_RUNTIME && __x86_64__) || CH_CHACHA20_AVX512_MODEL
