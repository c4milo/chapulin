#include "aead_avx512.h"

// The whole file compiles only under CH_AEAD_AVX512 (aead_avx512.h): in an
// x86-64 host object whose Poly1305 runs on the native multiply, or in a
// test unit over the lane models.
#ifdef CH_AEAD_AVX512

// A model build compiles chacha20_avx512.h's declaration too, so the define
// comes before the headers.
#if defined(CH_AEAD_AVX512_MODEL) && !defined(CH_CHACHA20_AVX512_MODEL)
#define CH_CHACHA20_AVX512_MODEL 1
#endif

// The file is a native copy alone: its Poly1305 groups run on the native
// multiply, as poly1305_ifma_native.c's do. The renames apply to every
// declaration the file includes after it, poly1305_update among them.
#include "widemul_native.h"

// These come before the attribute push below, so their declarations carry
// no target attribute, for the reason poly1305_ifma.c gives.
#include "avx512_wipe.h"
#include "ch_assert.h"
#include "chacha20.h"
#include "chacha20_avx512.h"
#include "ct.h"
#include "poly1305_ifma.h"
// carry_scalar alone: the groups compute their powers of r in the lanes.
#define POLY1305_SCALAR_CARRY_ONLY
#include "poly1305_scalar.h"

#ifdef CH_AEAD_AVX512_MODEL
// Each lane operation in portable C (test/chacha20_avx512_model_lanes.h and
// test/poly1305_ifma_model_lanes.h), which only a build with -Itest finds.
#include "poly1305_ifma_model_lanes.h"
#else
// Every function from here to the pop at the end of this file carries the
// target attribute that turns AVX-512F and AVX-512 IFMA on, and no function
// outside it does, as in chacha20_avx512.c and poly1305_ifma.c. The object
// is compiled with no instruction flag, so only these functions hold
// AVX-512 instructions, and aead.c calls them only for a session whose
// ch_cfg.cpu holds CH_CPU_AVX512_IFMA beside the multiply bit.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx512f,avx512ifma"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx512f,avx512ifma")
#endif

#include "poly1305_ifma_lanes.h"
#endif

#define CHACHA20_AVX512_PASS_INLINE 1
#include "chacha20_avx512_lanes.h"
#include "poly1305_ifma_group.h"

// The attribute that aligns a pass's frame to the widest slot the compiler
// gives a vector, for the reason chacha20_avx2.c's pass gives
// (docs/decisions.md 124). x86-64 alone has it, and a model build on
// another host compiles the passes without it. The passes also stay out of
// line: inlined into the seal, the first and the last made clang 23 keep
// 102 512-bit values in stack slots inside the seal's loops
// (docs/decisions.md 226).
#ifdef __x86_64__
#define FRAME_ALIGNMENT force_align_arg_pointer
#else
#define FRAME_ALIGNMENT noinline
#endif

// A pass of sixteen ChaCha20 blocks covers four Poly1305 groups of sixteen
// blocks. Each of the four is absorbed after an even double round, after
// double rounds 2, 4, 6 and 8 of the ten.
#define PASS_GROUPS 4
_Static_assert((size_t)PASS_GROUPS *POLY1305_IFMA_GROUP == PASS_BYTES,
               "the four groups of a pass are the pass's bytes");

// The group at m absorbed into the eight lanes of h, under the two
// multipliers every group but the last takes (poly1305_ifma_group.h).
static inline __attribute__((always_inline)) void
absorb_group(lanes h[3], const uint8_t *m, multiplier_read *first, multiplier_read *second) {
    lanes lo[3];
    lanes hi[3];
    group_sums(lo, hi, h, m, first, second);
    carry(h, lo, hi);
}

// The ten double rounds of the pass in x, and between them the four groups
// at hash absorbed into h. The rounds run on the vector units and the
// groups mostly on the multiplier, and neither waits on the other, so the
// CPU runs both at once. Where rows is not 0, the four rows of a row pass
// in y take the same ten double rounds in the same loop.
static inline __attribute__((always_inline)) void rounds_hashing(chacha_lanes x[16],
                                                                 chacha_lanes y[4], int rows,
                                                                 const uint8_t *hash, lanes h[3],
                                                                 const powers *of_r) {
    double_round(x);
    if (rows) {
        double_round_rows(y);
    }
    for (size_t g = 0; g < PASS_GROUPS; g++) {
        double_round(x);
        if (rows) {
            double_round_rows(y);
        }
        absorb_group(h, hash + POLY1305_IFMA_GROUP * g, &of_r->by_16, &of_r->by_8);
        double_round(x);
        if (rows) {
            double_round_rows(y);
        }
    }
    double_round(x);
    if (rows) {
        double_round_rows(y);
    }
}

// One pass of sixteen blocks from counter over in[0..limit), limit 1 to
// PASS_BYTES, with the four groups at hash absorbed into h between its
// rounds. The groups are read before the pass writes out, so hash may be
// in.
__attribute__((FRAME_ALIGNMENT, noinline)) static void
pass_hashing(const uint32_t words[16], uint32_t counter, const uint8_t *in, uint8_t *out,
             size_t limit, const uint8_t *hash, lanes h[3], const powers *of_r) {
    chacha_lanes x[16];
    lanes acc[3] = {h[0], h[1], h[2]};
    pass_input(x, words, counter);
    rounds_hashing(x, NULL, 0, hash, acc, of_r);
    pass_keystream(x, words, counter);
    chacha_lanes last = xor_blocks(in, out, x, limit);
    size_t whole = limit - limit % CHACHA20_BLOCK;
    if (whole < limit) {
        xor_partial(in + whole, out + whole, last, limit - whole);
    }
    h[0] = acc[0];
    h[1] = acc[1];
    h[2] = acc[2];
}

// The last whole pass, its groups, and a row pass of four blocks beside it
// over the rest bytes after it, rest 1 to ROW_PASS_BYTES, as
// chacha20_avx512.c's pass_with_rows runs a message's last bytes. The
// pass's bytes are written before the rest is read, so out <= in stays
// safe.
__attribute__((FRAME_ALIGNMENT, noinline)) static void
pass_hashing_rows(const uint32_t words[16], uint32_t counter, const uint8_t *in, uint8_t *out,
                  size_t rest, const uint8_t *hash, lanes h[3], const powers *of_r) {
    chacha_lanes x[16];
    chacha_lanes y[4];
    lanes acc[3] = {h[0], h[1], h[2]};
    pass_input(x, words, counter);
    rows_input(y, words, counter + PASS_BLOCKS);
    rounds_hashing(x, y, 1, hash, acc, of_r);
    pass_keystream(x, words, counter);
    (void)xor_blocks(in, out, x, PASS_BYTES);
    rows_keystream(y, words, counter + PASS_BLOCKS);
    xor_rows(in + PASS_BYTES, out + PASS_BYTES, y, rest);
    h[0] = acc[0];
    h[1] = acc[1];
    h[2] = acc[2];
}

// A pass with no group to absorb: the seal's first, whose ciphertext the
// second absorbs.
__attribute__((FRAME_ALIGNMENT, noinline)) static void
pass_plain(const uint32_t words[16], uint32_t counter, const uint8_t *in, uint8_t *out) {
    chacha_lanes x[16];
    pass_input(x, words, counter);
    for (int i = 0; i < 10; i++) {
        double_round(x);
    }
    pass_keystream(x, words, counter);
    (void)xor_blocks(in, out, x, PASS_BYTES);
}

// The lanes' start: lane 0 from p's accumulator and lanes 1 to 7 from 0, as
// poly1305_ifma_blocks starts them.
static void lanes_start(lanes h[3], const poly1305 *p) {
    uint64_t start[3];
    digits_of_words(start, p->h);
    h[0] = lanes_first_only(start[0]);
    h[1] = lanes_first_only(start[1]);
    h[2] = lanes_first_only(start[2]);
}

// The left bytes at m, the last of the message, absorbed: every whole group,
// the last under the multipliers it is owed, as poly1305_ifma_blocks ends;
// then the lanes' total written back to p, and the blocks and bytes after
// the groups through poly1305_update, the native copy's. left is
// POLY1305_IFMA_GROUP or more. The powers of r are wiped. The vector
// registers still hold the lanes, and poly1305_update's vector path may
// write powers of r to them, so each entry wipes them after this call.
static void hash_rest(poly1305 *p, lanes h[3], powers *of_r, const uint8_t *m, size_t left) {
    CH_ASSERT(left >= POLY1305_IFMA_GROUP);
    size_t groups = left / POLY1305_IFMA_GROUP;
    for (size_t g = 1; g < groups; g++) {
        absorb_group(h, m, &of_r->by_16, &of_r->by_8);
        m += POLY1305_IFMA_GROUP;
    }
    absorb_group(h, m, &of_r->last_first, &of_r->last_second);
    m += POLY1305_IFMA_GROUP;
    uint64_t total[3];
    total[0] = lanes_total(h[0]);
    total[1] = lanes_total(h[1]);
    total[2] = lanes_total(h[2]);
    words_of_totals(p->h, total);
    ct_wipe(of_r, sizeof *of_r);
    poly1305_update(p, m, left - groups * POLY1305_IFMA_GROUP);
}

// The block counter of the first block of pass number index: RFC 8439
// §2.8 starts the data at block 1, and the counter wraps modulo 2^32, as
// chacha20.c's does.
static uint32_t pass_counter(size_t index) {
    return (uint32_t)(1 + PASS_BLOCKS * index);
}

void aead_avx512_seal(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                      poly1305 *p, const uint8_t *pt, size_t n, uint8_t *ct) {
    CH_ASSERT(n >= AEAD_AVX512_MIN && p->fill == 0);
    size_t passes = n / PASS_BYTES;
    size_t rest = n % PASS_BYTES;
    uint32_t words[16];
    setup(words, key, nonce);
    powers of_r;
    compute_powers(&of_r, p->r);
    lanes h[3];
    lanes_start(h, p);
    // Pass 0 has no ciphertext before it to absorb. Each pass after it
    // absorbs the ciphertext the pass before it wrote, and the last whole
    // pass carries the rest when a row pass covers it.
    pass_plain(words, pass_counter(0), pt, ct);
    for (size_t index = 1; index < passes; index++) {
        size_t offset = PASS_BYTES * index;
        const uint8_t *hash = ct + offset - PASS_BYTES;
        if (index + 1 == passes && rest > 0 && rest <= ROW_PASS_BYTES) {
            pass_hashing_rows(words, pass_counter(index), pt + offset, ct + offset, rest, hash, h,
                              &of_r);
        } else {
            pass_hashing(words, pass_counter(index), pt + offset, ct + offset, PASS_BYTES, hash, h,
                         &of_r);
        }
    }
    // A rest longer than a row pass takes a pass of its own, which absorbs
    // the last whole pass. hashed counts the ciphertext bytes the passes
    // absorbed.
    size_t done = PASS_BYTES * passes;
    int rest_pass = rest > ROW_PASS_BYTES;
    if (rest_pass) {
        pass_hashing(words, pass_counter(passes), pt + done, ct + done, rest,
                     ct + done - PASS_BYTES, h, &of_r);
    }
    size_t hashed = rest_pass ? done : done - PASS_BYTES;
    ct_wipe(words, sizeof words);
    hash_rest(p, h, &of_r, ct + hashed, n - hashed);
    // The key, the keystream, the powers of r and the lanes passed through
    // the vector registers, and the compiler clears none of them on return.
    lanes_wipe_registers();
}

void aead_avx512_open(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                      poly1305 *p, const uint8_t *ct, size_t n, uint8_t *pt) {
    CH_ASSERT(n >= AEAD_AVX512_MIN && p->fill == 0);
    size_t passes = n / PASS_BYTES;
    uint32_t words[16];
    setup(words, key, nonce);
    powers of_r;
    compute_powers(&of_r, p->r);
    lanes h[3];
    lanes_start(h, p);
    // Each pass but the last whole one absorbs its own ciphertext before it
    // writes the plaintext. A pass writes pt + i at or below ct + i, so it
    // overwrites no byte that a later pass reads.
    for (size_t index = 0; index + 1 < passes; index++) {
        size_t offset = PASS_BYTES * index;
        pass_hashing(words, pass_counter(index), ct + offset, pt + offset, PASS_BYTES, ct + offset,
                     h, &of_r);
    }
    ct_wipe(words, sizeof words);
    // The rest, the last whole pass and the bytes after it, is absorbed
    // whole, and then decrypted on chacha20_avx512.c's kernel, which wipes
    // every vector register before it returns, as the seal's last step
    // does.
    size_t hashed = PASS_BYTES * (passes - 1);
    hash_rest(p, h, &of_r, ct + hashed, n - hashed);
    chacha20_avx512_xor(key, nonce, pass_counter(passes - 1), ct + hashed, pt + hashed, n - hashed);
}

#ifndef CH_AEAD_AVX512_MODEL
#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif
#endif

#endif // CH_AEAD_AVX512
