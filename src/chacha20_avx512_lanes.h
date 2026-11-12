// The lane operations and the pass of the AVX-512 ChaCha20, which
// chacha20_avx512.c's keystream and aead_avx512.c's one-pass
// ChaCha20-Poly1305 both run, so the kernel has one text
// (docs/decisions.md 121 and 226). A lane operation is one AVX-512F
// instruction on a 512-bit register of sixteen 32-bit lanes, lane 0 in bits
// 31..0. test/chacha20_avx512_model_lanes.h defines the same names in
// portable C, which a unit that defines CH_CHACHA20_AVX512_MODEL reads in
// place of the instructions, so the text runs on any CPU and CBMC can read
// it.
//
// Only chacha20_avx512.c and aead_avx512.c include this file, between the
// attribute push that turns AVX-512F on and its pop, so every function here
// carries that target and none outside the two kernels does. Each operation
// works on all sixteen lanes at once and has no branch and no memory access
// that depends on a lane's value. The calls take a lane's word as an int;
// the casts below keep its 32 bits, which is how gcc and clang define the
// conversion of a value above INT_MAX.
#ifndef CH_CHACHA20_AVX512_LANES_H
#define CH_CHACHA20_AVX512_LANES_H

#include <stddef.h>
#include <stdint.h>

#include "chacha20.h"
#include "ct.h"

// The lane operations exist over the model in a test unit, and on the
// instructions in a host object on x86-64; every other build reads none of
// this file.
#ifdef CH_CHACHA20_AVX512_MODEL
#include "chacha20_avx512_model_lanes.h"
#define CH_CHACHA20_AVX512_LANES 1
#elif defined(CH_CPU_RUNTIME) && defined(__x86_64__)
#define CH_CHACHA20_AVX512_LANES 1
#include <immintrin.h>

typedef __m512i chacha_lanes;

// word in every lane: VPBROADCASTD.
static inline chacha_lanes chacha_lanes_broadcast(uint32_t word) {
    return _mm512_set1_epi32((int)word);
}

// Every lane 0: VPXORD of a register with itself.
static inline chacha_lanes chacha_lanes_zero(void) {
    return _mm512_setzero_si512();
}

// Each lane of a plus the same lane of b, modulo 2^32: VPADDD.
static inline chacha_lanes chacha_lanes_add(chacha_lanes a, chacha_lanes b) {
    return _mm512_add_epi32(a, b);
}

// VPXORD.
static inline chacha_lanes chacha_lanes_xor(chacha_lanes a, chacha_lanes b) {
    return _mm512_xor_si512(a, b);
}

// VPROLD: each lane rotated left by a constant count. One function per
// count, because the instruction takes the count as an immediate.
static inline chacha_lanes chacha_lanes_rotate_left_16(chacha_lanes x) {
    return _mm512_rol_epi32(x, 16);
}

static inline chacha_lanes chacha_lanes_rotate_left_12(chacha_lanes x) {
    return _mm512_rol_epi32(x, 12);
}

static inline chacha_lanes chacha_lanes_rotate_left_8(chacha_lanes x) {
    return _mm512_rol_epi32(x, 8);
}

static inline chacha_lanes chacha_lanes_rotate_left_7(chacha_lanes x) {
    return _mm512_rol_epi32(x, 7);
}

// counter + j in lane j, j from 0 to 15, modulo 2^32, as chacha20.c's
// state[12]++ wraps: VPBROADCASTD and VPADDD of a constant.
// _mm512_setr_epi32 names the lanes from 0 up.
static inline chacha_lanes chacha_lanes_counters(uint32_t counter) {
    return _mm512_add_epi32(
        _mm512_set1_epi32((int)counter),
        _mm512_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15));
}

// Within each 128-bit quarter, lanes 0 and 1 of the quarter of a and of b
// in the order a0 b0 a1 b1: VPUNPCKLDQ. The high form takes lanes 2 and 3:
// VPUNPCKHDQ.
static inline chacha_lanes chacha_lanes_interleave_low_32(chacha_lanes a, chacha_lanes b) {
    return _mm512_unpacklo_epi32(a, b);
}

static inline chacha_lanes chacha_lanes_interleave_high_32(chacha_lanes a, chacha_lanes b) {
    return _mm512_unpackhi_epi32(a, b);
}

// The same of 64-bit pairs of lanes: VPUNPCKLQDQ and VPUNPCKHQDQ.
static inline chacha_lanes chacha_lanes_interleave_low_64(chacha_lanes a, chacha_lanes b) {
    return _mm512_unpacklo_epi64(a, b);
}

static inline chacha_lanes chacha_lanes_interleave_high_64(chacha_lanes a, chacha_lanes b) {
    return _mm512_unpackhi_epi64(a, b);
}

// VSHUFI32X4: two 128-bit quarters of a and two of b, in the order its
// constant names. 0x44 takes quarters 0 and 1 of each, 0xee quarters 2 and
// 3, 0x88 quarters 0 and 2, and 0xdd quarters 1 and 3. One function per
// constant, because the instruction takes it as an immediate.
static inline chacha_lanes chacha_lanes_quarters_0101(chacha_lanes a, chacha_lanes b) {
    return _mm512_shuffle_i32x4(a, b, 0x44);
}

static inline chacha_lanes chacha_lanes_quarters_2323(chacha_lanes a, chacha_lanes b) {
    return _mm512_shuffle_i32x4(a, b, 0xee);
}

static inline chacha_lanes chacha_lanes_quarters_0202(chacha_lanes a, chacha_lanes b) {
    return _mm512_shuffle_i32x4(a, b, 0x88);
}

static inline chacha_lanes chacha_lanes_quarters_1313(chacha_lanes a, chacha_lanes b) {
    return _mm512_shuffle_i32x4(a, b, 0xdd);
}

// VPSHUFD within each 128-bit quarter under a constant order: 0x39 turns
// the quarter's four words left by one, 0x4e by two and 0x93 by three.
static inline chacha_lanes chacha_lanes_turn_1(chacha_lanes x) {
    return _mm512_shuffle_epi32(x, (_MM_PERM_ENUM)0x39);
}

static inline chacha_lanes chacha_lanes_turn_2(chacha_lanes x) {
    return _mm512_shuffle_epi32(x, (_MM_PERM_ENUM)0x4e);
}

static inline chacha_lanes chacha_lanes_turn_3(chacha_lanes x) {
    return _mm512_shuffle_epi32(x, (_MM_PERM_ENUM)0x93);
}

// The four words at words in every 128-bit quarter, word i in lane 4k + i:
// VBROADCASTI32X4 from memory.
static inline chacha_lanes chacha_lanes_row(const uint32_t words[4]) {
    return _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i *)(const void *)words));
}

// The last row of four blocks, block k in quarter k: counter + k in lane
// 4k, and the three nonce words in lanes 4k + 1 to 4k + 3. VBROADCASTI32X4
// and VPADDD of a constant.
static inline chacha_lanes chacha_lanes_row_counters(uint32_t counter, const uint32_t nonce[3]) {
    __m128i last = _mm_setr_epi32((int)counter, (int)nonce[0], (int)nonce[1], (int)nonce[2]);
    return _mm512_add_epi32(_mm512_broadcast_i32x4(last),
                            _mm512_setr_epi32(0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0));
}

// The 64 bytes at bytes, lane j from bytes 4j to 4j + 3, little-endian:
// VMOVDQU32, which takes any address.
static inline chacha_lanes chacha_lanes_load(const uint8_t *bytes) {
    return _mm512_loadu_si512((const void *)bytes);
}

// x written to the 64 bytes at bytes, as chacha_lanes_load reads them.
static inline void chacha_lanes_store(uint8_t *bytes, chacha_lanes x) {
    _mm512_storeu_si512((void *)bytes, x);
}

// Every vector register and k1 to k7 zeroed: avx512_wipe.h's one call, a
// block of assembly, because C names no register. The includer includes
// avx512_wipe.h before its attribute push, as poly1305_ifma.c says why.
static inline void chacha_lanes_wipe_registers(void) {
    avx512_wipe_registers();
}
#endif // CH_CHACHA20_AVX512_MODEL, or CH_CPU_RUNTIME and __x86_64__

#ifdef CH_CHACHA20_AVX512_LANES

// aead_avx512.c runs Poly1305's groups between the double rounds of a
// pass, and gcc 13 compiled its rounds and the pass's end out of line,
// which passes the state through the stack. So aead_avx512.c defines
// CHACHA20_AVX512_PASS_INLINE before it includes this file, and the pieces
// of a pass carry always_inline there. chacha20_avx512.c defines nothing,
// and its code is what the compilers chose for it (docs/decisions.md 121).
#ifdef CHACHA20_AVX512_PASS_INLINE
#define PASS_INLINE_ATTRIBUTE always_inline
#else
#define PASS_INLINE_ATTRIBUTE unused
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

// A 4x4 transpose of 32-bit words in each 128-bit quarter, which the
// interleaves work in: within each quarter, lane j of a, b, c and d becomes
// lanes 0 to 3 of the j-th of them. Quarter k of the inputs holds lanes 4k
// to 4k + 3, so quarter k of the outputs holds four words of each of blocks
// 4k to 4k + 3.
static inline __attribute__((PASS_INLINE_ATTRIBUTE)) void
transpose_words(chacha_lanes *a, chacha_lanes *b, chacha_lanes *c, chacha_lanes *d) {
    chacha_lanes ab_low = chacha_lanes_interleave_low_32(*a, *b);
    chacha_lanes cd_low = chacha_lanes_interleave_low_32(*c, *d);
    chacha_lanes ab_high = chacha_lanes_interleave_high_32(*a, *b);
    chacha_lanes cd_high = chacha_lanes_interleave_high_32(*c, *d);
    *a = chacha_lanes_interleave_low_64(ab_low, cd_low);
    *b = chacha_lanes_interleave_high_64(ab_low, cd_low);
    *c = chacha_lanes_interleave_low_64(ab_high, cd_high);
    *d = chacha_lanes_interleave_high_64(ab_high, cd_high);
}

// A 4x4 transpose of 128-bit quarters: quarter k of a, b, c and d becomes
// quarters 0 to 3 of the k-th of them.
static inline __attribute__((PASS_INLINE_ATTRIBUTE)) void
transpose_quarters(chacha_lanes *a, chacha_lanes *b, chacha_lanes *c, chacha_lanes *d) {
    chacha_lanes ab_low = chacha_lanes_quarters_0101(*a, *b);  // a0 a1 b0 b1
    chacha_lanes ab_high = chacha_lanes_quarters_2323(*a, *b); // a2 a3 b2 b3
    chacha_lanes cd_low = chacha_lanes_quarters_0101(*c, *d);  // c0 c1 d0 d1
    chacha_lanes cd_high = chacha_lanes_quarters_2323(*c, *d); // c2 c3 d2 d3
    *a = chacha_lanes_quarters_0202(ab_low, cd_low);           // a0 b0 c0 d0
    *b = chacha_lanes_quarters_1313(ab_low, cd_low);           // a1 b1 c1 d1
    *c = chacha_lanes_quarters_0202(ab_high, cd_high);         // a2 b2 c2 d2
    *d = chacha_lanes_quarters_1313(ab_high, cd_high);         // a3 b3 c3 d3
}

static uint32_t load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// chacha20.c's QUARTERROUND on sixteen lanes at once.
static inline __attribute__((PASS_INLINE_ATTRIBUTE)) void
quarter_round(chacha_lanes *a, chacha_lanes *b, chacha_lanes *c, chacha_lanes *d) {
    *a = chacha_lanes_add(*a, *b);
    *d = chacha_lanes_rotate_left_16(chacha_lanes_xor(*d, *a));
    *c = chacha_lanes_add(*c, *d);
    *b = chacha_lanes_rotate_left_12(chacha_lanes_xor(*b, *c));
    *a = chacha_lanes_add(*a, *b);
    *d = chacha_lanes_rotate_left_8(chacha_lanes_xor(*d, *a));
    *c = chacha_lanes_add(*c, *d);
    *b = chacha_lanes_rotate_left_7(chacha_lanes_xor(*b, *c));
}

// One double round of RFC 8439 §2.3 on the pass: the four column rounds,
// then the four diagonal rounds, as chacha20.c's block runs them.
static inline __attribute__((PASS_INLINE_ATTRIBUTE)) void double_round(chacha_lanes x[16]) {
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
static inline __attribute__((PASS_INLINE_ATTRIBUTE)) void
pass_input(chacha_lanes x[16], const uint32_t words[16], uint32_t counter) {
#pragma GCC unroll 16
    for (size_t w = 0; w < 16; w++) {
        x[w] = chacha_lanes_broadcast(words[w]);
    }
    x[12] = chacha_lanes_counters(counter);
}

// The end of each block of the pass in x after its ten double rounds: the
// input added back, as RFC 8439 §2.3 ends a block, and the two transposes.
// On return x[b] holds block b's 64 bytes in order, word 0 in its lowest
// lane.
static inline __attribute__((PASS_INLINE_ATTRIBUTE)) void
pass_keystream(chacha_lanes x[16], const uint32_t words[16], uint32_t counter) {
    chacha_lanes input[16];
    pass_input(input, words, counter);
#pragma GCC unroll 16
    for (size_t w = 0; w < 16; w++) {
        x[w] = chacha_lanes_add(x[w], input[w]);
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
static void xor_partial(const uint8_t *in, uint8_t *out, chacha_lanes keystream, size_t count) {
    uint8_t bytes[CHACHA20_BLOCK];
    chacha_lanes_store(bytes, keystream);
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
static inline __attribute__((PASS_INLINE_ATTRIBUTE)) chacha_lanes
xor_blocks(const uint8_t *in, uint8_t *out, const chacha_lanes x[16], size_t limit) {
#pragma GCC unroll 16
    for (size_t b = 0; b < PASS_BLOCKS; b++) {
        size_t offset = CHACHA20_BLOCK * b;
        if (offset + CHACHA20_BLOCK > limit) {
            return x[b];
        }
        chacha_lanes data = chacha_lanes_load(in + offset);
        chacha_lanes_store(out + offset, chacha_lanes_xor(data, x[b]));
    }
    return chacha_lanes_zero();
}

// A row pass: four blocks in four vectors, row r of block k in quarter k
// of vector r, as chacha20.c's state lays a block out in rows of four
// words. The column round runs on the rows as they are, and the diagonal
// round on rows 1 to 3 turned by one, two and three words within each
// quarter, as a one-block SIMD ChaCha20 runs: VPSHUFD under a constant
// order, so which word moves where depends on the order alone.
//
// The four rows of the blocks counter to counter + 3, block k in quarter k.
static inline __attribute__((PASS_INLINE_ATTRIBUTE)) void
rows_input(chacha_lanes y[4], const uint32_t words[16], uint32_t counter) {
    y[0] = chacha_lanes_row(&words[0]);
    y[1] = chacha_lanes_row(&words[4]);
    y[2] = chacha_lanes_row(&words[8]);
    y[3] = chacha_lanes_row_counters(counter, &words[13]);
}

// One double round on the row pass.
static inline __attribute__((PASS_INLINE_ATTRIBUTE)) void double_round_rows(chacha_lanes y[4]) {
    quarter_round(&y[0], &y[1], &y[2], &y[3]);
    y[1] = chacha_lanes_turn_1(y[1]);
    y[2] = chacha_lanes_turn_2(y[2]);
    y[3] = chacha_lanes_turn_3(y[3]);
    quarter_round(&y[0], &y[1], &y[2], &y[3]);
    y[1] = chacha_lanes_turn_3(y[1]);
    y[2] = chacha_lanes_turn_2(y[2]);
    y[3] = chacha_lanes_turn_1(y[3]);
}

// The input added back, and the quarters transposed: y[k] holds block k's
// 64 bytes in order.
static inline __attribute__((PASS_INLINE_ATTRIBUTE)) void
rows_keystream(chacha_lanes y[4], const uint32_t words[16], uint32_t counter) {
    chacha_lanes input[4];
    rows_input(input, words, counter);
    for (size_t r = 0; r < 4; r++) {
        y[r] = chacha_lanes_add(y[r], input[r]);
    }
    transpose_quarters(&y[0], &y[1], &y[2], &y[3]);
}

// out[0..n) = in[0..n) XOR the row pass's keystream, n from 1 to
// ROW_PASS_BYTES: the whole blocks first, in ascending order, and then the
// last 1 to 63 bytes. Only n, which is public, decides which blocks run.
static void xor_rows(const uint8_t *in, uint8_t *out, const chacha_lanes y[4], size_t n) {
    for (size_t b = 0; b < ROW_PASS_BLOCKS; b++) {
        size_t offset = CHACHA20_BLOCK * b;
        if (offset + CHACHA20_BLOCK > n) {
            if (offset < n) {
                xor_partial(in + offset, out + offset, y[b], n - offset);
            }
            return;
        }
        chacha_lanes data = chacha_lanes_load(in + offset);
        chacha_lanes_store(out + offset, chacha_lanes_xor(data, y[b]));
    }
}

#endif // CH_CHACHA20_AVX512_LANES

#endif
