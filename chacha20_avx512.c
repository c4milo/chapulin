#include "chacha20_avx512.h"

// The whole file compiles only in a host object on x86-64
// (chacha20_avx512.h).
#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

#include <immintrin.h>

#include "avx512_wipe.h"
#include "ct.h"

// Every function from here to the pop at the end of this file carries the
// target attribute that turns AVX-512F on, and no function outside it does,
// as in chacha20_avx2.c. clang applies it through one attribute push; gcc's
// target pragma sets it for each function defined after it, until the pop.
// The object is compiled with no instruction flag, so only these functions
// hold AVX-512 instructions, and chacha20.c calls them only where the
// caller's CH_CPU_AVX512_IFMA bit says the CPU has AVX-512F.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx512f"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx512f")
#endif

// A pass is sixteen blocks: word w of each of the sixteen sits in one
// 32-bit lane of the vector that holds word w, block b in lane b.
#define PASS_BLOCKS 16
#define PASS_BYTES ((size_t)PASS_BLOCKS * CHACHA20_BLOCK)
// A row pass is four blocks, one in each 128-bit quarter of four vectors:
// it serves the last 1 to ROW_PASS_BYTES bytes of a message.
#define ROW_PASS_BLOCKS 4
#define ROW_PASS_BYTES ((size_t)ROW_PASS_BLOCKS * CHACHA20_BLOCK)
// gcc does not expand a macro in the pragma, so the counts are written out
// and the assertion holds them.
_Static_assert(PASS_BLOCKS == 16, "the #pragma GCC unroll 16 below writes PASS_BLOCKS out");

// Sixteen 32-bit lanes in one AVX-512 register. The calls take a lane's
// word as an int; the casts below keep its 32 bits, which is how gcc and
// clang define the conversion of a value above INT_MAX. Each operation
// below works on all sixteen lanes at once and has no branch and no memory
// access that depends on a lane's value.
typedef __m512i lanes;

static inline lanes lanes_broadcast(uint32_t word) {
    return _mm512_set1_epi32((int)word);
}

static inline lanes lanes_add(lanes a, lanes b) {
    return _mm512_add_epi32(a, b);
}

static inline lanes lanes_xor(lanes a, lanes b) {
    return _mm512_xor_si512(a, b);
}

// VPROLD: each lane rotated left by a constant count. One function per
// count, because the instruction takes the count as an immediate.
static inline lanes lanes_rotate_left_16(lanes x) {
    return _mm512_rol_epi32(x, 16);
}

static inline lanes lanes_rotate_left_12(lanes x) {
    return _mm512_rol_epi32(x, 12);
}

static inline lanes lanes_rotate_left_8(lanes x) {
    return _mm512_rol_epi32(x, 8);
}

static inline lanes lanes_rotate_left_7(lanes x) {
    return _mm512_rol_epi32(x, 7);
}

// counter to counter + 15 in lanes 0 to 15. The lane adds wrap modulo
// 2^32, as chacha20.c's state[12]++ does. _mm512_setr_epi32 names the
// lanes from 0 up.
static inline lanes lanes_counters(uint32_t counter) {
    return _mm512_add_epi32(
        _mm512_set1_epi32((int)counter),
        _mm512_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15));
}

// A 4x4 transpose of 32-bit words in each 128-bit quarter, which the
// unpack instructions work in: within each quarter, lane j of a, b, c and d
// becomes lanes 0 to 3 of the j-th of them. Quarter k of the inputs holds
// lanes 4k to 4k + 3, so quarter k of the outputs holds four words of each
// of blocks 4k to 4k + 3.
static inline void transpose_words(lanes *a, lanes *b, lanes *c, lanes *d) {
    lanes ab_low = _mm512_unpacklo_epi32(*a, *b);
    lanes cd_low = _mm512_unpacklo_epi32(*c, *d);
    lanes ab_high = _mm512_unpackhi_epi32(*a, *b);
    lanes cd_high = _mm512_unpackhi_epi32(*c, *d);
    *a = _mm512_unpacklo_epi64(ab_low, cd_low);
    *b = _mm512_unpackhi_epi64(ab_low, cd_low);
    *c = _mm512_unpacklo_epi64(ab_high, cd_high);
    *d = _mm512_unpackhi_epi64(ab_high, cd_high);
}

// A 4x4 transpose of 128-bit quarters: quarter k of a, b, c and d becomes
// quarters 0 to 3 of the k-th of them. VSHUFI32X4 takes two quarters of
// its first operand and two of its second, in the order its constant
// names: 0x44 takes quarters 0 and 1 of each, 0xee quarters 2 and 3, 0x88
// quarters 0 and 2, and 0xdd quarters 1 and 3.
static inline void transpose_quarters(lanes *a, lanes *b, lanes *c, lanes *d) {
    lanes ab_low = _mm512_shuffle_i32x4(*a, *b, 0x44);  // a0 a1 b0 b1
    lanes ab_high = _mm512_shuffle_i32x4(*a, *b, 0xee); // a2 a3 b2 b3
    lanes cd_low = _mm512_shuffle_i32x4(*c, *d, 0x44);  // c0 c1 d0 d1
    lanes cd_high = _mm512_shuffle_i32x4(*c, *d, 0xee); // c2 c3 d2 d3
    *a = _mm512_shuffle_i32x4(ab_low, cd_low, 0x88);    // a0 b0 c0 d0
    *b = _mm512_shuffle_i32x4(ab_low, cd_low, 0xdd);    // a1 b1 c1 d1
    *c = _mm512_shuffle_i32x4(ab_high, cd_high, 0x88);  // a2 b2 c2 d2
    *d = _mm512_shuffle_i32x4(ab_high, cd_high, 0xdd);  // a3 b3 c3 d3
}

static uint32_t load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// chacha20.c's QUARTERROUND on sixteen lanes at once.
static inline void quarter_round(lanes *a, lanes *b, lanes *c, lanes *d) {
    *a = lanes_add(*a, *b);
    *d = lanes_rotate_left_16(lanes_xor(*d, *a));
    *c = lanes_add(*c, *d);
    *b = lanes_rotate_left_12(lanes_xor(*b, *c));
    *a = lanes_add(*a, *b);
    *d = lanes_rotate_left_8(lanes_xor(*d, *a));
    *c = lanes_add(*c, *d);
    *b = lanes_rotate_left_7(lanes_xor(*b, *c));
}

// One double round of RFC 8439 §2.3 on the pass: the four column rounds,
// then the four diagonal rounds, as chacha20.c's block runs them.
static inline void double_round(lanes x[16]) {
    quarter_round(&x[0], &x[4], &x[8], &x[12]);
    quarter_round(&x[1], &x[5], &x[9], &x[13]);
    quarter_round(&x[2], &x[6], &x[10], &x[14]);
    quarter_round(&x[3], &x[7], &x[11], &x[15]);
    quarter_round(&x[0], &x[5], &x[10], &x[15]);
    quarter_round(&x[1], &x[6], &x[11], &x[12]);
    quarter_round(&x[2], &x[7], &x[8], &x[13]);
    quarter_round(&x[3], &x[4], &x[9], &x[14]);
}

// The input words of RFC 8439 §2.3 in chacha20.c's order: the constants,
// the key and the nonce. Word 12, the block counter, differs by block, so
// the passes set it and this leaves it 0.
static void setup(uint32_t words[16], const uint8_t key[CHACHA20_KEY],
                  const uint8_t nonce[CHACHA20_NONCE]) {
    words[0] = 0x61707865;
    words[1] = 0x3320646e;
    words[2] = 0x79622d32;
    words[3] = 0x6b206574;
    for (size_t i = 0; i < 8; i++) {
        words[4 + i] = load32(key + 4 * i);
    }
    words[12] = 0;
    words[13] = load32(nonce);
    words[14] = load32(nonce + 4);
    words[15] = load32(nonce + 8);
}

// The input of the pass whose blocks have the counters counter to
// counter + 15: word w of every block in x[w], one block per lane.
static inline void pass_input(lanes x[16], const uint32_t words[16], uint32_t counter) {
#pragma GCC unroll 16
    for (size_t w = 0; w < 16; w++) {
        x[w] = lanes_broadcast(words[w]);
    }
    x[12] = lanes_counters(counter);
}

// The end of each block of the pass in x after its ten double rounds: the
// input added back, as RFC 8439 §2.3 ends a block, and the two transposes.
// On return x[b] holds block b's 64 bytes in order, word 0 in its lowest
// lane.
static inline void pass_keystream(lanes x[16], const uint32_t words[16], uint32_t counter) {
    lanes input[16];
    pass_input(input, words, counter);
#pragma GCC unroll 16
    for (size_t w = 0; w < 16; w++) {
        x[w] = lanes_add(x[w], input[w]);
    }
    transpose_words(&x[0], &x[1], &x[2], &x[3]);
    transpose_words(&x[4], &x[5], &x[6], &x[7]);
    transpose_words(&x[8], &x[9], &x[10], &x[11]);
    transpose_words(&x[12], &x[13], &x[14], &x[15]);
    // Quarter k of x[4g + j] now holds words 4g to 4g + 3 of block 4k + j.
    transpose_quarters(&x[0], &x[4], &x[8], &x[12]);
    transpose_quarters(&x[1], &x[5], &x[9], &x[13]);
    transpose_quarters(&x[2], &x[6], &x[10], &x[14]);
    transpose_quarters(&x[3], &x[7], &x[11], &x[15]);
}

// out[0..count) = in[0..count) XOR the first count bytes of keystream, for
// the last 1 to 63 bytes of a message. The keystream passes through a
// buffer of 64 bytes, which the call wipes before it returns.
static void xor_partial(const uint8_t *in, uint8_t *out, lanes keystream, size_t count) {
    uint8_t bytes[CHACHA20_BLOCK];
    _mm512_storeu_si512((void *)bytes, keystream);
    for (size_t i = 0; i < count; i++) {
        out[i] = in[i] ^ bytes[i];
    }
    ct_wipe(bytes, sizeof bytes);
}

// XORs block b's keystream, x[b], into each block of 64 bytes that
// out[0..limit) and in[0..limit) hold whole, in ascending order. Each 64
// bytes are read before the 64 at the same offset are written, so out <= in
// is safe as it is in chacha20.c. Returns the keystream of the first block
// it leaves, or a zero vector when it XORs all 16. Only the limit, which is
// public, decides which blocks run.
static inline lanes xor_blocks(const uint8_t *in, uint8_t *out, const lanes x[16], size_t limit) {
#pragma GCC unroll 16
    for (size_t b = 0; b < PASS_BLOCKS; b++) {
        size_t offset = CHACHA20_BLOCK * b;
        if (offset + CHACHA20_BLOCK > limit) {
            return x[b];
        }
        lanes data = _mm512_loadu_si512((const void *)(in + offset));
        _mm512_storeu_si512((void *)(out + offset), lanes_xor(data, x[b]));
    }
    return _mm512_setzero_si512();
}

// One pass: the sixteen blocks whose counters start at counter, their ten
// double rounds, and their keystream XORed into each whole block of
// out[0..limit), for a limit of 1 to PASS_BYTES. Returns the keystream of
// the block the limit ends inside, whose first limit % 64 bytes the caller
// XORs when limit % 64 is not 0.
static lanes pass(const uint32_t words[16], uint32_t counter, const uint8_t *in, uint8_t *out,
                  size_t limit) {
    lanes x[16];
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
    lanes last = pass(words, counter, in, out, n);
    size_t whole = n - n % CHACHA20_BLOCK;
    if (whole < n) {
        xor_partial(in + whole, out + whole, last, n - whole);
    }
}

// A row pass: four blocks in four vectors, row r of block k in quarter k
// of vector r, as chacha20.c's state lays a block out in rows of four
// words. The column round runs on the rows as they are, and the diagonal
// round on rows 1 to 3 turned by one, two and three words within each
// quarter, as a one-block SIMD ChaCha20 runs: VPSHUFD under a constant
// order, so which word moves where depends on the order alone.
//
// The four rows of the blocks counter to counter + 3, block k in quarter k.
static inline void rows_input(lanes y[4], const uint32_t words[16], uint32_t counter) {
    y[0] = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i *)(const void *)&words[0]));
    y[1] = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i *)(const void *)&words[4]));
    y[2] = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i *)(const void *)&words[8]));
    __m128i last = _mm_setr_epi32((int)counter, (int)words[13], (int)words[14], (int)words[15]);
    y[3] = _mm512_add_epi32(_mm512_broadcast_i32x4(last),
                            _mm512_setr_epi32(0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0));
}

// One double round on the row pass. VPSHUFD's order 0x39 turns a row left
// by one word, 0x4e by two and 0x93 by three, within each quarter.
static inline void double_round_rows(lanes y[4]) {
    quarter_round(&y[0], &y[1], &y[2], &y[3]);
    y[1] = _mm512_shuffle_epi32(y[1], (_MM_PERM_ENUM)0x39);
    y[2] = _mm512_shuffle_epi32(y[2], (_MM_PERM_ENUM)0x4e);
    y[3] = _mm512_shuffle_epi32(y[3], (_MM_PERM_ENUM)0x93);
    quarter_round(&y[0], &y[1], &y[2], &y[3]);
    y[1] = _mm512_shuffle_epi32(y[1], (_MM_PERM_ENUM)0x93);
    y[2] = _mm512_shuffle_epi32(y[2], (_MM_PERM_ENUM)0x4e);
    y[3] = _mm512_shuffle_epi32(y[3], (_MM_PERM_ENUM)0x39);
}

// The input added back, and the quarters transposed: y[k] holds block k's
// 64 bytes in order.
static inline void rows_keystream(lanes y[4], const uint32_t words[16], uint32_t counter) {
    lanes input[4];
    rows_input(input, words, counter);
    for (size_t r = 0; r < 4; r++) {
        y[r] = lanes_add(y[r], input[r]);
    }
    transpose_quarters(&y[0], &y[1], &y[2], &y[3]);
}

// out[0..n) = in[0..n) XOR the row pass's keystream, n from 1 to
// ROW_PASS_BYTES: the whole blocks first, in ascending order, and then the
// last 1 to 63 bytes. Only n, which is public, decides which blocks run.
static void xor_rows(const uint8_t *in, uint8_t *out, const lanes y[4], size_t n) {
    for (size_t b = 0; b < ROW_PASS_BLOCKS; b++) {
        size_t offset = CHACHA20_BLOCK * b;
        if (offset + CHACHA20_BLOCK > n) {
            if (offset < n) {
                xor_partial(in + offset, out + offset, y[b], n - offset);
            }
            return;
        }
        lanes data = _mm512_loadu_si512((const void *)(in + offset));
        _mm512_storeu_si512((void *)(out + offset), lanes_xor(data, y[b]));
    }
}

// A message of 1 to ROW_PASS_BYTES bytes: one row pass.
static void row_pass(const uint32_t words[16], uint32_t counter, const uint8_t *in, uint8_t *out,
                     size_t n) {
    lanes y[4];
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
    lanes x[16];
    lanes y[4];
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
    // The key, the state and the keystream passed through the vector
    // registers, and the compiler clears none of them on return.
    avx512_wipe_registers();
}

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif

#endif // CH_CPU_RUNTIME && __x86_64__
