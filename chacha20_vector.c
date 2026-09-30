#include "chacha20_vector.h"

// The whole file compiles only under CH_CHACHA_VECTOR (chacha20_vector.h).
#ifdef CH_CHACHA_VECTOR

#ifdef __ARM_NEON
#include <arm_neon.h>
#else
#include <emmintrin.h>
#endif

#include "ct.h"

// One group is four blocks: word w of each of the four sits in one lane of
// the vector that holds word w.
#define GROUP_BLOCKS 4
#define GROUP_BYTES ((size_t)GROUP_BLOCKS * CHACHA20_BLOCK)

// The groups one pass computes side by side. Each quarter round is a chain
// of operations that each wait on the one before, and one group runs four
// such chains at a time. On the M1 Pro that left the vector units waiting:
// two groups a pass, eight chains, took about 40% less time per block for
// the same operations. arm64's 32 vector registers hold two groups' 32
// words, with a few of them kept on the stack. SSE2's 16 registers hold
// one group's 16 words, and no x86-64 machine here has timed a second
// group (docs/decisions.md 86). Each loop over a pass's groups carries
// #pragma GCC unroll 2, which gcc and clang both read: gcc keeps an array
// that a rolled loop indexes in memory. gcc does not expand a macro in the
// pragma, so the count is written out and the assertion holds it.
#ifdef __ARM_NEON
#define PASS_GROUPS 2
#else
#define PASS_GROUPS 1
#endif
_Static_assert(PASS_GROUPS <= 2, "each #pragma GCC unroll 2 below covers PASS_GROUPS");
#define PASS_BYTES ((size_t)PASS_GROUPS * GROUP_BYTES)

// The vector operations the rounds below are written in, one set per
// instruction set. Each operates on all four lanes at once and has no
// branch and no memory access that depends on a lane's value.

#ifdef __ARM_NEON

// Four 32-bit lanes in one NEON register.
typedef uint32x4_t lanes;

static inline lanes lanes_broadcast(uint32_t word) {
    return vdupq_n_u32(word);
}

static inline lanes lanes_add(lanes a, lanes b) {
    return vaddq_u32(a, b);
}

static inline lanes lanes_xor(lanes a, lanes b) {
    return veorq_u32(a, b);
}

// A rotation by 16 swaps the two 16-bit halves of each lane.
static inline lanes lanes_rotate_left_16(lanes x) {
    return vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x)));
}

// The other rotations shift left by r, then shift right by 32 - r and
// insert the result into the bits the left shift cleared (SRI).
static inline lanes lanes_rotate_left_12(lanes x) {
    return vsriq_n_u32(vshlq_n_u32(x, 12), x, 20);
}

static inline lanes lanes_rotate_left_8(lanes x) {
    return vsriq_n_u32(vshlq_n_u32(x, 8), x, 24);
}

static inline lanes lanes_rotate_left_7(lanes x) {
    return vsriq_n_u32(vshlq_n_u32(x, 7), x, 25);
}

// counter, counter + 1, counter + 2 and counter + 3 in lanes 0 to 3. The
// lane adds wrap modulo 2^32, as chacha20.c's state[12]++ does.
static inline lanes lanes_counters(uint32_t counter) {
    static const uint32_t offsets[4] = {0, 1, 2, 3};
    return vaddq_u32(vdupq_n_u32(counter), vld1q_u32(offsets));
}

// A 4x4 transpose of 32-bit words: lane j of a, b, c and d becomes lanes 0
// to 3 of the j-th of them.
static inline void transpose(lanes *a, lanes *b, lanes *c, lanes *d) {
    uint32x4x2_t ab = vtrnq_u32(*a, *b); // a0 b0 a2 b2, and a1 b1 a3 b3
    uint32x4x2_t cd = vtrnq_u32(*c, *d); // c0 d0 c2 d2, and c1 d1 c3 d3
    *a = vcombine_u32(vget_low_u32(ab.val[0]), vget_low_u32(cd.val[0]));   // a0 b0 c0 d0
    *b = vcombine_u32(vget_low_u32(ab.val[1]), vget_low_u32(cd.val[1]));   // a1 b1 c1 d1
    *c = vcombine_u32(vget_high_u32(ab.val[0]), vget_high_u32(cd.val[0])); // a2 b2 c2 d2
    *d = vcombine_u32(vget_high_u32(ab.val[1]), vget_high_u32(cd.val[1])); // a3 b3 c3 d3
}

// out[0..15] = in[0..15] XOR the keystream's 16 bytes, lane 0's four bytes
// first. The 16 input bytes are read before any output byte is written.
static inline void xor_16(const uint8_t *in, uint8_t *out, lanes keystream) {
    vst1q_u8(out, veorq_u8(vld1q_u8(in), vreinterpretq_u8_u32(keystream)));
}

static inline void store_16(uint8_t *out, lanes keystream) {
    vst1q_u8(out, vreinterpretq_u8_u32(keystream));
}

#else

// Four 32-bit lanes in one SSE2 register. The SSE2 calls take a lane's
// word as an int; the casts below keep its 32 bits, which is how gcc and
// clang define the conversion of a value above INT_MAX.
typedef __m128i lanes;

static inline lanes lanes_broadcast(uint32_t word) {
    return _mm_set1_epi32((int)word);
}

static inline lanes lanes_add(lanes a, lanes b) {
    return _mm_add_epi32(a, b);
}

static inline lanes lanes_xor(lanes a, lanes b) {
    return _mm_xor_si128(a, b);
}

// SSE2 has no rotation, so each one shifts left by r, shifts right by
// 32 - r, and ORs the two.
static inline lanes lanes_rotate_left_16(lanes x) {
    return _mm_or_si128(_mm_slli_epi32(x, 16), _mm_srli_epi32(x, 16));
}

static inline lanes lanes_rotate_left_12(lanes x) {
    return _mm_or_si128(_mm_slli_epi32(x, 12), _mm_srli_epi32(x, 20));
}

static inline lanes lanes_rotate_left_8(lanes x) {
    return _mm_or_si128(_mm_slli_epi32(x, 8), _mm_srli_epi32(x, 24));
}

static inline lanes lanes_rotate_left_7(lanes x) {
    return _mm_or_si128(_mm_slli_epi32(x, 7), _mm_srli_epi32(x, 25));
}

// counter, counter + 1, counter + 2 and counter + 3 in lanes 0 to 3. The
// lane adds wrap modulo 2^32, as chacha20.c's state[12]++ does.
// _mm_set_epi32 names the lanes from 3 down to 0.
static inline lanes lanes_counters(uint32_t counter) {
    return _mm_add_epi32(_mm_set1_epi32((int)counter), _mm_set_epi32(3, 2, 1, 0));
}

// A 4x4 transpose of 32-bit words: lane j of a, b, c and d becomes lanes 0
// to 3 of the j-th of them.
static inline void transpose(lanes *a, lanes *b, lanes *c, lanes *d) {
    lanes ab_low = _mm_unpacklo_epi32(*a, *b);  // a0 b0 a1 b1
    lanes cd_low = _mm_unpacklo_epi32(*c, *d);  // c0 d0 c1 d1
    lanes ab_high = _mm_unpackhi_epi32(*a, *b); // a2 b2 a3 b3
    lanes cd_high = _mm_unpackhi_epi32(*c, *d); // c2 d2 c3 d3
    *a = _mm_unpacklo_epi64(ab_low, cd_low);    // a0 b0 c0 d0
    *b = _mm_unpackhi_epi64(ab_low, cd_low);    // a1 b1 c1 d1
    *c = _mm_unpacklo_epi64(ab_high, cd_high);  // a2 b2 c2 d2
    *d = _mm_unpackhi_epi64(ab_high, cd_high);  // a3 b3 c3 d3
}

// out[0..15] = in[0..15] XOR the keystream's 16 bytes, lane 0's four bytes
// first. The 16 input bytes are read before any output byte is written.
static inline void xor_16(const uint8_t *in, uint8_t *out, lanes keystream) {
    lanes data = _mm_loadu_si128((const __m128i *)(const void *)in);
    _mm_storeu_si128((__m128i *)(void *)out, _mm_xor_si128(data, keystream));
}

static inline void store_16(uint8_t *out, lanes keystream) {
    _mm_storeu_si128((__m128i *)(void *)out, keystream);
}

#endif

static uint32_t load32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// chacha20.c's QUARTERROUND on four lanes at once.
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

// One double round of RFC 8439 §2.3 on one group: the four column
// rounds, then the four diagonal rounds, as chacha20.c's block runs them.
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
// group_input sets it and this leaves it 0.
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

// The input of the group whose blocks have the counters counter to
// counter + 3: word w of every block in x[w], one block per lane.
static inline void group_input(lanes x[16], const uint32_t words[16], uint32_t counter) {
#pragma GCC unroll 16
    for (size_t w = 0; w < 16; w++) {
        x[w] = lanes_broadcast(words[w]);
    }
    x[12] = lanes_counters(counter);
}

// The end of each block of the group in x after its ten double rounds:
// the input added back, as RFC 8439 §2.3 ends a block, and a transpose
// into block order. On return x[4 * g + b] holds bytes 16 * g to
// 16 * g + 15 of block b: words 4 * g to 4 * g + 3 of that block.
static inline void group_keystream(lanes x[16], const uint32_t words[16], uint32_t counter) {
    lanes input[16];
    group_input(input, words, counter);
#pragma GCC unroll 16
    for (size_t w = 0; w < 16; w++) {
        x[w] = lanes_add(x[w], input[w]);
    }
    // x[w] holds word w of the four blocks. Each transpose turns four
    // consecutive words of the four blocks into four words of each block.
    transpose(&x[0], &x[1], &x[2], &x[3]);
    transpose(&x[4], &x[5], &x[6], &x[7]);
    transpose(&x[8], &x[9], &x[10], &x[11]);
    transpose(&x[12], &x[13], &x[14], &x[15]);
}

// out[0..count) = in[0..count) XOR the first count bytes of keystream,
// for the last 1 to 15 bytes of a message. The keystream passes through
// a buffer of 16 bytes, which the call wipes before it returns.
static void xor_partial(const uint8_t *in, uint8_t *out, lanes keystream, size_t count) {
    uint8_t bytes[16];
    store_16(bytes, keystream);
    for (size_t i = 0; i < count; i++) {
        out[i] = in[i] ^ bytes[i];
    }
    ct_wipe(bytes, sizeof bytes);
}

// XORs the group's keystream in x, in block order as group_keystream
// leaves it, into each row of 16 bytes that out[0..limit) and
// in[0..limit) hold whole, 16 bytes at a time in ascending order. Each 16
// bytes are read before the 16 at the same offset are written, so out <=
// in is safe as it is in chacha20.c. Returns the keystream of the first
// row it leaves, or next when it XORs all 16. Only the limit, which is
// public, decides which rows run.
static inline lanes xor_rows(const uint8_t *in, uint8_t *out, const lanes x[16], size_t limit,
                             lanes next) {
#pragma GCC unroll 16
    for (size_t row = 0; row < 16; row++) {
        // Row 4 * b + g of the group is bytes 16 * g to 16 * g + 15 of
        // block b, which x[4 * g + b] holds.
        size_t offset = 16 * row;
        lanes keystream = x[4 * (row % 4) + row / 4];
        if (offset + 16 > limit) {
            return keystream;
        }
        xor_16(in + offset, out + offset, keystream);
    }
    return next;
}

// One pass: the PASS_GROUPS groups whose blocks start at the counter
// counter, their ten double rounds run side by side, and their keystream
// XORed into each whole row of 16 bytes that out[0..limit) and
// in[0..limit) hold, for a limit of 1 to PASS_BYTES. Returns the
// keystream of the row the limit ends inside, whose first limit % 16
// bytes the caller XORs when limit % 16 is not 0. A pass with a limit
// below PASS_BYTES is the message's last, and it computes every group of
// the pass, since the groups run side by side.
static lanes pass(const uint32_t words[16], uint32_t counter, const uint8_t *in, uint8_t *out,
                  size_t limit) {
    lanes x[PASS_GROUPS][16];
#pragma GCC unroll 2
    for (size_t g = 0; g < PASS_GROUPS; g++) {
        group_input(x[g], words, counter + (uint32_t)(GROUP_BLOCKS * g));
    }
    for (int i = 0; i < 10; i++) {
#pragma GCC unroll 2
        for (size_t g = 0; g < PASS_GROUPS; g++) {
            double_round(x[g]);
        }
    }
    lanes next = lanes_broadcast(0);
#pragma GCC unroll 2
    for (size_t g = 0; g < PASS_GROUPS; g++) {
        size_t start = GROUP_BYTES * g;
        if (start < limit) {
            group_keystream(x[g], words, counter + (uint32_t)(GROUP_BLOCKS * g));
            next = xor_rows(in + start, out + start, x[g], limit - start, next);
        }
    }
    return next;
}

void chacha20_vector_xor(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                         uint32_t counter, const uint8_t *in, uint8_t *out, size_t n) {
    uint32_t words[16];
    setup(words, key, nonce);
    while (n >= PASS_BYTES) {
        (void)pass(words, counter, in, out, PASS_BYTES);
        counter += PASS_GROUPS * GROUP_BLOCKS;
        in += PASS_BYTES;
        out += PASS_BYTES;
        n -= PASS_BYTES;
    }
    if (n > 0) {
        // The last 1 to PASS_BYTES - 1 bytes: the whole rows in the pass,
        // and the last 1 to 15 bytes, when there are any, one at a time,
        // as chacha20.c XORs its last block.
        lanes last = pass(words, counter, in, out, n);
        size_t whole = n - n % 16;
        if (whole < n) {
            xor_partial(in + whole, out + whole, last, n - whole);
        }
    }
}

#endif // CH_CHACHA_VECTOR
