#include "aead_avx2.h"

// The whole file compiles only under CH_AEAD_AVX2 (aead_avx2.h): in an
// x86-64 host object whose Poly1305 runs on the native multiply.
#ifdef CH_AEAD_AVX2

// The file is a native copy alone: its Poly1305 steps run on the native
// multiply, as poly1305_avx2_native.c's do. The renames apply to every
// declaration the file includes after it, poly1305_update_avx2 among them.
#include "widemul_native.h"

#include "ch_assert.h"
#include "poly1305_avx2.h"
#include "poly1305_wide.h"

#ifndef CH_POLY1305_AVX2
#error "aead_avx2.c needs poly1305_avx2.c's kernel: an x86-64 host object's native copy"
#endif

// Every function from here to the pop at the end of this file carries the
// target attribute that turns AVX2 on, and no function outside it does,
// as in chacha20_avx2.c and poly1305_avx2.c. poly1305_wide.h's step,
// included above, compiles without it, and runs on the general registers
// alone. aead.c calls the two entries only
// where the caller's CH_CPU_AVX2 bit says the CPU has AVX2.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx2"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx2")
#endif

#include "chacha20_avx2_lanes.h"

// A pass covers PASS_BYTES, 32 Poly1305 blocks. Each of the ten double
// rounds below absorbs three, and the last two follow the rounds.
#define POLY1305_BLOCK ((size_t)16)
#define DOUBLE_ROUNDS ((size_t)10)
#define STEP_BLOCKS ((size_t)3)
#define LAST_BLOCKS ((size_t)2)
_Static_assert((DOUBLE_ROUNDS * STEP_BLOCKS + LAST_BLOCKS) * POLY1305_BLOCK == PASS_BYTES,
               "the rounds and the two blocks after them absorb a pass's blocks");

// One pass of eight ChaCha20 blocks, as chacha20_avx2_lanes.h's pass with a
// limit of PASS_BYTES, and between its rounds the 32 blocks at hash
// absorbed into acc on the general registers (poly1305_wide.h). The rounds
// run on the vector units and the blocks on the scalar multiplier, and
// neither waits on the other, so the CPU runs both at once. The blocks
// are read before the pass writes out, so hash may be in. The attribute
// aligns the frame to 32 bytes, for the reason pass gives.
//
// A block's step waits for the step before it, and a round waits for no
// block. Four blocks after a double round took longer than the double
// round, and the last two double rounds absorbed none. So each double
// round absorbs three: two after its column round and one after its
// diagonal round. The last two run beside the keystream's adds and its
// transposes (docs/decisions.md 211).
__attribute__((force_align_arg_pointer)) static void
pass_hashing(const uint32_t input[16], uint32_t counter, const uint8_t *in, uint8_t *out,
             const uint8_t *hash, poly1305_wide_acc *acc, const poly1305_wide_key *key) {
    poly1305_wide_acc a = *acc;
    const poly1305_wide_key k = *key;
    lanes x[16];
    pass_input(x, input, counter);
    for (size_t step = 0; step < DOUBLE_ROUNDS; step++) {
        const uint8_t *m = hash + STEP_BLOCKS * POLY1305_BLOCK * step;
        column_round(x);
        poly1305_wide_block(&a, &k, m);
        poly1305_wide_block(&a, &k, m + POLY1305_BLOCK);
        diagonal_round(x);
        poly1305_wide_block(&a, &k, m + 2 * POLY1305_BLOCK);
    }
    const uint8_t *last = hash + DOUBLE_ROUNDS * STEP_BLOCKS * POLY1305_BLOCK;
    poly1305_wide_block(&a, &k, last);
    poly1305_wide_block(&a, &k, last + POLY1305_BLOCK);
    pass_keystream(x, input, counter);
    (void)xor_rows(in, out, x, PASS_BYTES);
    *acc = a;
}

// The accumulator written back to p, and the n bytes at m, the last bytes
// of the message, absorbed into p by poly1305_update_avx2: n holds
// PASS_BYTES or more, so its whole groups run on poly1305_avx2.c's kernel.
// The accumulator and the key are wiped.
static void hash_rest(poly1305_wide_acc *acc, poly1305_wide_key *key, poly1305 *p, const uint8_t *m,
                      size_t n) {
    poly1305_wide_to_words(p->h, acc);
    ct_wipe(acc, sizeof *acc);
    ct_wipe(key, sizeof *key);
    poly1305_update_avx2(p, m, n);
}

// The block counter of the first block of pass number index: RFC 8439
// §2.8 starts the data at block 1, and the counter wraps modulo 2^32, as
// chacha20.c's does.
static uint32_t pass_counter(size_t index) {
    return (uint32_t)(1 + PASS_BLOCKS * index);
}

void aead_avx2_seal(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                    poly1305 *p, const uint8_t *pt, size_t n, uint8_t *ct) {
    CH_ASSERT(n >= AEAD_AVX2_MIN && p->fill == 0);
    size_t passes = n / PASS_BYTES;
    uint32_t input[16];
    setup(input, key, nonce);
    poly1305_wide_key r;
    poly1305_wide_acc acc;
    poly1305_wide_key_of(&r, p->r);
    poly1305_wide_from_words(&acc, p->h);
    // Pass 0 has no ciphertext before it to absorb. Each pass after it
    // absorbs the ciphertext the pass before it wrote.
    (void)pass(input, pass_counter(0), pt, ct, PASS_BYTES);
    for (size_t index = 1; index < passes; index++) {
        size_t offset = PASS_BYTES * index;
        pass_hashing(input, pass_counter(index), pt + offset, ct + offset, ct + offset - PASS_BYTES,
                     &acc, &r);
    }
    size_t done = PASS_BYTES * passes;
    xor_message(input, pass_counter(passes), pt + done, ct + done, n - done);
    ct_wipe(input, sizeof input);
    size_t hashed = done - PASS_BYTES;
    hash_rest(&acc, &r, p, ct + hashed, n - hashed);
    _mm256_zeroall();
}

void aead_avx2_open(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                    poly1305 *p, const uint8_t *ct, size_t n, uint8_t *pt) {
    CH_ASSERT(n >= AEAD_AVX2_MIN && p->fill == 0);
    size_t passes = n / PASS_BYTES;
    uint32_t input[16];
    setup(input, key, nonce);
    poly1305_wide_key r;
    poly1305_wide_acc acc;
    poly1305_wide_key_of(&r, p->r);
    poly1305_wide_from_words(&acc, p->h);
    // Each pass but the last whole one absorbs its own ciphertext before
    // it writes the plaintext. A pass writes pt + i at or below ct + i,
    // so it overwrites no byte that a later pass reads.
    for (size_t index = 0; index + 1 < passes; index++) {
        size_t offset = PASS_BYTES * index;
        pass_hashing(input, pass_counter(index), ct + offset, pt + offset, ct + offset, &acc, &r);
    }
    // The rest, the last whole pass and the bytes after it, is absorbed
    // whole and then decrypted.
    size_t hashed = PASS_BYTES * (passes - 1);
    hash_rest(&acc, &r, p, ct + hashed, n - hashed);
    xor_message(input, pass_counter(passes - 1), ct + hashed, pt + hashed, n - hashed);
    ct_wipe(input, sizeof input);
    _mm256_zeroall();
}

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif

#endif // CH_AEAD_AVX2
