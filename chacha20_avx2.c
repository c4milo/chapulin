#include "chacha20_avx2.h"

// The whole file compiles only in a host object on x86-64
// (chacha20_avx2.h).
#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

#include <immintrin.h>

#include "ct.h"

// Every function from here to the pop at the end of this file carries the
// target attribute that turns AVX2 on, and no function outside it does.
// clang applies it through one attribute push; gcc's target pragma sets
// it for each function defined after it, until the pop. The object is
// compiled with no instruction flag, so only these functions hold AVX2
// instructions, and chacha20.c calls them only where the caller's
// CH_CPU_AVX2 bit says the CPU has AVX2.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx2"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx2")
#endif

// A pass is eight blocks: word w of each of the eight sits in one 32-bit
// lane of the vector that holds word w, block b in lane b. AVX2 has 16
// vector registers, which one pass's 16 words fill, so the compilers keep
// a few words on the stack while the rounds run (docs/decisions.md 90).
#define PASS_BLOCKS 8
#define PASS_BYTES ((size_t)PASS_BLOCKS * CHACHA20_BLOCK)
// A row is the 32 bytes one vector XORs into the data: half a block.
#define ROW_BYTES 32
#define PASS_ROWS (PASS_BYTES / ROW_BYTES)
// gcc does not expand a macro in the pragma, so the counts are written
// out and the assertion holds them.
_Static_assert(PASS_ROWS == 16, "the #pragma GCC unroll 16 below writes PASS_ROWS out");

// Eight 32-bit lanes in one AVX2 register. The AVX2 calls take a lane's
// word as an int; the casts below keep its 32 bits, which is how gcc and
// clang define the conversion of a value above INT_MAX. Each operation
// below works on all eight lanes at once and has no branch and no memory
// access that depends on a lane's value.
typedef __m256i lanes;

static inline lanes lanes_broadcast(uint32_t word) {
    return _mm256_set1_epi32((int)word);
}

static inline lanes lanes_add(lanes a, lanes b) {
    return _mm256_add_epi32(a, b);
}

static inline lanes lanes_xor(lanes a, lanes b) {
    return _mm256_xor_si256(a, b);
}

// A rotation by 16 or by 8 moves whole bytes inside each lane, so one byte
// shuffle (VPSHUFB) does it: byte i of each 16 bytes of the result is
// byte order[i] of the same 16 bytes of x. A lane's least significant byte
// comes first in memory, so a rotation left by 16 swaps the lane's two
// halves, and a rotation left by 8 moves byte 3 to byte 0 and bytes 0 to
// 2 up one place. The order is a constant, so which byte moves where
// depends on nothing the cipher computes.
static inline lanes lanes_rotate_left_16(lanes x) {
    const lanes order = _mm256_setr_epi8(2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3,
                                         0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
    return _mm256_shuffle_epi8(x, order);
}

static inline lanes lanes_rotate_left_8(lanes x) {
    const lanes order = _mm256_setr_epi8(3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, 3, 0,
                                         1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);
    return _mm256_shuffle_epi8(x, order);
}

// The other two rotations shift left by r, shift right by 32 - r, and OR
// the two, as chacha20_vector.c's SSE2 rotations do.
static inline lanes lanes_rotate_left_12(lanes x) {
    return _mm256_or_si256(_mm256_slli_epi32(x, 12), _mm256_srli_epi32(x, 20));
}

static inline lanes lanes_rotate_left_7(lanes x) {
    return _mm256_or_si256(_mm256_slli_epi32(x, 7), _mm256_srli_epi32(x, 25));
}

// counter to counter + 7 in lanes 0 to 7. The lane adds wrap modulo 2^32,
// as chacha20.c's state[12]++ does. _mm256_setr_epi32 names the lanes from
// 0 up.
static inline lanes lanes_counters(uint32_t counter) {
    return _mm256_add_epi32(_mm256_set1_epi32((int)counter),
                            _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7));
}

// A 4x4 transpose of 32-bit words in each 128-bit half, which AVX2's
// unpack instructions work in: within each half, lane j of a, b, c and d
// becomes lanes 0 to 3 of the j-th of them. The low half holds lanes 0 to
// 3 and the high half lanes 4 to 7.
static inline void transpose(lanes *a, lanes *b, lanes *c, lanes *d) {
    lanes ab_low = _mm256_unpacklo_epi32(*a, *b);  // a0 b0 a1 b1, a4 b4 a5 b5
    lanes cd_low = _mm256_unpacklo_epi32(*c, *d);  // c0 d0 c1 d1, c4 d4 c5 d5
    lanes ab_high = _mm256_unpackhi_epi32(*a, *b); // a2 b2 a3 b3, a6 b6 a7 b7
    lanes cd_high = _mm256_unpackhi_epi32(*c, *d); // c2 d2 c3 d3, c6 d6 c7 d7
    *a = _mm256_unpacklo_epi64(ab_low, cd_low);    // a0 b0 c0 d0, a4 b4 c4 d4
    *b = _mm256_unpackhi_epi64(ab_low, cd_low);    // a1 b1 c1 d1, a5 b5 c5 d5
    *c = _mm256_unpacklo_epi64(ab_high, cd_high);  // a2 b2 c2 d2, a6 b6 c6 d6
    *d = _mm256_unpackhi_epi64(ab_high, cd_high);  // a3 b3 c3 d3, a7 b7 c7 d7
}

// out[0..31] = in[0..31] XOR the keystream's 32 bytes, lane 0's four bytes
// first. The 32 input bytes are read before any output byte is written.
static inline void xor_32(const uint8_t *in, uint8_t *out, lanes keystream) {
    lanes data = _mm256_loadu_si256((const __m256i *)(const void *)in);
    _mm256_storeu_si256((__m256i *)(void *)out, _mm256_xor_si256(data, keystream));
}

static inline void store_32(uint8_t *out, lanes keystream) {
    _mm256_storeu_si256((__m256i *)(void *)out, keystream);
}

static uint32_t load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// chacha20.c's QUARTERROUND on eight lanes at once.
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
// the key and the nonce. Word 12, the block counter, differs by lane, so
// pass_input sets it and this leaves it 0.
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
// counter + 7: word w of every block in x[w], one block per lane.
static inline void pass_input(lanes x[16], const uint32_t words[16], uint32_t counter) {
#pragma GCC unroll 16
    for (size_t w = 0; w < 16; w++) {
        x[w] = lanes_broadcast(words[w]);
    }
    x[12] = lanes_counters(counter);
}

// The end of each block of the pass in x after its ten double rounds: the
// input added back, as RFC 8439 §2.3 ends a block, and a transpose of each
// four consecutive words. On return, for b from 0 to 3, x[4 * g + b]
// holds words 4 * g to 4 * g + 3 of block b in its low half and of block
// b + 4 in its high half.
static inline void pass_keystream(lanes x[16], const uint32_t words[16], uint32_t counter) {
    lanes input[16];
    pass_input(input, words, counter);
#pragma GCC unroll 16
    for (size_t w = 0; w < 16; w++) {
        x[w] = lanes_add(x[w], input[w]);
    }
    transpose(&x[0], &x[1], &x[2], &x[3]);
    transpose(&x[4], &x[5], &x[6], &x[7]);
    transpose(&x[8], &x[9], &x[10], &x[11]);
    transpose(&x[12], &x[13], &x[14], &x[15]);
}

// The keystream of row row of the pass in x, as pass_keystream leaves it:
// bytes 32 * row to 32 * row + 31 of the pass, which are words
// 8 * (row % 2) to 8 * (row % 2) + 7 of block row / 2. Those words sit in
// two vectors, x[first] and x[first + 4], in the low halves for blocks 0
// to 3 and in the high halves for blocks 4 to 7. VPERM2I128 joins the two
// halves: 0x20 takes both low halves and 0x31 both high ones. row is a
// loop index, so the branch reads nothing secret.
static inline lanes row_keystream(const lanes x[16], size_t row) {
    size_t block = row / 2;
    size_t first = 8 * (row % 2) + block % 4;
    if (block < 4) {
        return _mm256_permute2x128_si256(x[first], x[first + 4], 0x20);
    }
    return _mm256_permute2x128_si256(x[first], x[first + 4], 0x31);
}

// out[0..count) = in[0..count) XOR the first count bytes of keystream,
// for the last 1 to 31 bytes of a message. The keystream passes through
// a buffer of 32 bytes, which the call wipes before it returns.
static void xor_partial(const uint8_t *in, uint8_t *out, lanes keystream, size_t count) {
    uint8_t bytes[ROW_BYTES];
    store_32(bytes, keystream);
    for (size_t i = 0; i < count; i++) {
        out[i] = in[i] ^ bytes[i];
    }
    ct_wipe(bytes, sizeof bytes);
}

// XORs the pass's keystream in x, as pass_keystream leaves it, into each
// row of 32 bytes that out[0..limit) and in[0..limit) hold whole, 32 bytes
// at a time in ascending order. Each 32 bytes are read before the 32 at
// the same offset are written, so out <= in is safe as it is in
// chacha20.c. Returns the keystream of the first row it leaves, or a zero
// vector when it XORs all 16. Only the limit, which is public, decides
// which rows run.
static inline lanes xor_rows(const uint8_t *in, uint8_t *out, const lanes x[16], size_t limit) {
#pragma GCC unroll 16
    for (size_t row = 0; row < PASS_ROWS; row++) {
        size_t offset = ROW_BYTES * row;
        lanes keystream = row_keystream(x, row);
        if (offset + ROW_BYTES > limit) {
            return keystream;
        }
        xor_32(in + offset, out + offset, keystream);
    }
    return lanes_broadcast(0);
}

// One pass: the eight blocks whose counters start at counter, their ten
// double rounds, and their keystream XORed into each whole row of 32
// bytes that out[0..limit) and in[0..limit) hold, for a limit of 1 to
// PASS_BYTES. Returns the keystream of the row the limit ends inside,
// whose first limit % 32 bytes the caller XORs when limit % 32 is not 0.
// A pass with a limit below PASS_BYTES is the message's last, and it
// computes all eight blocks, since the lanes run side by side.
static lanes pass(const uint32_t words[16], uint32_t counter, const uint8_t *in, uint8_t *out,
                  size_t limit) {
    lanes x[16];
    pass_input(x, words, counter);
    for (int i = 0; i < 10; i++) {
        double_round(x);
    }
    pass_keystream(x, words, counter);
    return xor_rows(in, out, x, limit);
}

void chacha20_avx2_xor(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                       uint32_t counter, const uint8_t *in, uint8_t *out, size_t n) {
    uint32_t words[16];
    setup(words, key, nonce);
    while (n >= PASS_BYTES) {
        (void)pass(words, counter, in, out, PASS_BYTES);
        counter += PASS_BLOCKS;
        in += PASS_BYTES;
        out += PASS_BYTES;
        n -= PASS_BYTES;
    }
    if (n > 0) {
        // The last 1 to PASS_BYTES - 1 bytes: the whole rows in the pass,
        // and the last 1 to 31 bytes, when there are any, one at a time,
        // as chacha20.c XORs its last block.
        lanes last = pass(words, counter, in, out, n);
        size_t whole = n - n % ROW_BYTES;
        if (whole < n) {
            xor_partial(in + whole, out + whole, last, n - whole);
        }
    }
}

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif

#endif // CH_CPU_RUNTIME && __x86_64__
