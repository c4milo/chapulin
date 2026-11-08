#include "aead_avx2.h"

// The whole file compiles only under CH_AEAD_AVX2 (aead_avx2.h): in an
// x86-64 host object whose Poly1305 runs on the native multiply.
#ifdef CH_AEAD_AVX2

// The file is a native copy alone: its Poly1305 groups and the powers of r
// run on the native multiply, as poly1305_avx2_native.c's do. The renames
// apply to every declaration the file includes after it.
#include "widemul_native.h"

#include "ch_assert.h"
#include "poly1305_avx2.h"
#include "poly1305_scalar.h"

#ifndef CH_POLY1305_AVX2
#error "aead_avx2.c needs poly1305_avx2.c's kernel: an x86-64 host object's native copy"
#endif

// Every function from here to the pop at the end of this file carries the
// target attribute that turns AVX2 on, and no function outside it does,
// as in chacha20_avx2.c and poly1305_avx2.c. poly1305_scalar.h's steps,
// included above, compile without it. aead.c calls the two entries only
// where the caller's CH_CPU_AVX2 bit says the CPU has AVX2.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx2"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx2")
#endif

#include "chacha20_avx2_lanes.h"
#include "poly1305_avx2_lanes.h"

// A ChaCha20 pass covers PASS_BYTES, which are this many Poly1305 groups.
#define PASS_GROUPS (PASS_BYTES / POLY1305_AVX2_GROUP)
_Static_assert(PASS_GROUPS == 4, "the round loop below absorbs one group every two rounds");

// One pass of eight ChaCha20 blocks, as chacha20_avx2_lanes.h's pass with a
// limit of PASS_BYTES, and between its double rounds the four groups at
// hash, none of them the last of the run, absorbed into h. The rounds and
// the groups do not depend on each other, so the CPU runs their
// instructions side by side. The groups are read before the pass writes
// out, so hash may be in. The attribute aligns the frame to 32 bytes, for
// the reason pass gives.
__attribute__((force_align_arg_pointer)) static void
pass_hashing(const uint32_t input[16], uint32_t counter, const uint8_t *in, uint8_t *out,
             const uint8_t *hash, words h[5], const powers *of_r) {
    lanes x[16];
    pass_input(x, input, counter);
    for (size_t group = 0; group < PASS_GROUPS; group++) {
        double_round(x);
        double_round(x);
        run_group(h, hash + POLY1305_AVX2_GROUP * group, of_r);
    }
    double_round(x);
    double_round(x);
    pass_keystream(x, input, counter);
    (void)xor_rows(in, out, x, PASS_BYTES);
}

// The n bytes at m, the last bytes of the message, absorbed into h and
// then into p: the whole groups, the last group of the run among them,
// then the blocks and the bytes after them through poly1305_update. n
// holds PASS_BYTES or more, so at least one group is left for the end.
// run_finish wipes of_r. Its group loop keeps 256-bit values in stack
// slots, so the attribute aligns the frame, as for pass_hashing.
__attribute__((force_align_arg_pointer)) static void
hash_rest(powers *of_r, words h[5], poly1305 *p, const uint8_t *m, size_t n) {
    size_t grouped = n - n % POLY1305_AVX2_GROUP;
    run_finish(of_r, h, p, m, grouped);
    poly1305_update(p, m + grouped, n - grouped);
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
    powers of_r;
    words h[5];
    run_start(&of_r, h, p);
    // Pass 0 has no ciphertext before it to absorb. Each pass after it
    // absorbs the ciphertext the pass before it wrote.
    (void)pass(input, pass_counter(0), pt, ct, PASS_BYTES);
    for (size_t index = 1; index < passes; index++) {
        size_t offset = PASS_BYTES * index;
        pass_hashing(input, pass_counter(index), pt + offset, ct + offset, ct + offset - PASS_BYTES,
                     h, &of_r);
    }
    size_t done = PASS_BYTES * passes;
    xor_message(input, pass_counter(passes), pt + done, ct + done, n - done);
    size_t hashed = done - PASS_BYTES;
    hash_rest(&of_r, h, p, ct + hashed, n - hashed);
    ct_wipe(input, sizeof input);
    _mm256_zeroall();
}

void aead_avx2_open(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                    poly1305 *p, const uint8_t *ct, size_t n, uint8_t *pt) {
    CH_ASSERT(n >= AEAD_AVX2_MIN && p->fill == 0);
    size_t passes = n / PASS_BYTES;
    uint32_t input[16];
    setup(input, key, nonce);
    powers of_r;
    words h[5];
    run_start(&of_r, h, p);
    // Each pass but the last whole one absorbs its own ciphertext before
    // it writes the plaintext. A pass writes pt + i at or below ct + i,
    // so it overwrites no byte that a later pass reads.
    for (size_t index = 0; index + 1 < passes; index++) {
        size_t offset = PASS_BYTES * index;
        pass_hashing(input, pass_counter(index), ct + offset, pt + offset, ct + offset, h, &of_r);
    }
    // The rest, the last whole pass and the bytes after it, is absorbed
    // whole and then decrypted.
    size_t hashed = PASS_BYTES * (passes - 1);
    hash_rest(&of_r, h, p, ct + hashed, n - hashed);
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
