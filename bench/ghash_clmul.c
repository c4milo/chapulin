// PROTOTYPE FOR MEASUREMENT ONLY. The library does not contain this code,
// no build of chapulin links it, and nothing here is proved: no CBMC
// harness, no Lean spec and no Wycheproof run covers it. It exists so
// bench/aead.sh can show what a GHASH on the carry-less multiply
// instruction costs beside quic_gcm.c's bit-by-bit one. bench/aead.c
// compares its output with gcm_ghash on random inputs before it times it,
// and stops if one byte differs.
//
// What it does. GHASH multiplies in GF(2^128) (SP 800-38D §6.3). That
// multiply is a carry-less product of two 128-bit values followed by a
// reduction modulo x^128 + x^7 + x^2 + x + 1. The instruction computes a
// carry-less product of two 64-bit values, so one block takes four of
// them, the schoolbook split of each operand into two halves. The
// reduction runs in plain 64-bit shifts and exclusive-ors.
//
// What it leaves out. It hashes one block per multiply and keeps no
// table of the powers of H, so it does not overlap the multiplies of
// several blocks. It computes the four products without Karatsuba's
// three. It moves each 128-bit product out of the vector register into
// two 64-bit words before it combines them. A production GHASH does all
// of these, so this prototype is slower than one would be.
//
// Bit order. SP 800-38D writes a block as a polynomial whose x^0
// coefficient is the most significant bit of byte 0. Reading the 16
// bytes big-endian into a 128-bit integer therefore puts x^0 at integer
// bit 127 and x^127 at bit 0: the coefficients are reversed. The
// carry-less product of two reversed values is the reversed product
// shifted right by one bit, so the code shifts it left by one before it
// reduces. The reduction is Gueron and Kounavis's for this bit order
// (Intel, "Carry-Less Multiplication Instruction and its Usage for
// Computing the GCM Mode", Algorithm 5).
#include "ghash_clmul.h"

#ifdef GHASH_CLMUL_INSTRUCTION

#include <string.h>

#ifdef __ARM_FEATURE_AES
#include <arm_neon.h>

// high:low = the 128-bit carry-less product of a and b.
static void carryless_multiply(uint64_t a, uint64_t b, uint64_t *high, uint64_t *low) {
    uint64x2_t product = vreinterpretq_u64_p128(vmull_p64((poly64_t)a, (poly64_t)b));
    *low = vgetq_lane_u64(product, 0);
    *high = vgetq_lane_u64(product, 1);
}
#else
#include <wmmintrin.h>

// high:low = the 128-bit carry-less product of a and b.
static void carryless_multiply(uint64_t a, uint64_t b, uint64_t *high, uint64_t *low) {
    __m128i product = _mm_clmulepi64_si128(_mm_cvtsi64_si128((long long)a),
                                           _mm_cvtsi64_si128((long long)b), 0x00);
    *low = (uint64_t)_mm_cvtsi128_si64(product);
    *high = (uint64_t)_mm_cvtsi128_si64(_mm_unpackhi_epi64(product, product));
}
#endif

// One GF(2^128) element as a 128-bit integer in two words: high holds
// bytes 0 to 7 of the block, low holds bytes 8 to 15.
typedef struct {
    uint64_t high;
    uint64_t low;
} ghash_element;

static uint64_t load_big_endian_64(const uint8_t p[8]) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; i++) {
        value = (value << 8) | p[i];
    }
    return value;
}

static void store_big_endian_64(uint8_t p[8], uint64_t value) {
    for (size_t i = 0; i < 8; i++) {
        p[i] = (uint8_t)(value >> (8 * (7 - i)));
    }
}

// x * h in GF(2^128), both in the reversed bit order the file header
// describes.
static ghash_element multiply(ghash_element x, ghash_element h) {
    uint64_t low_high = 0;
    uint64_t low_low = 0;
    uint64_t high_high = 0;
    uint64_t high_low = 0;
    uint64_t cross1_high = 0;
    uint64_t cross1_low = 0;
    uint64_t cross2_high = 0;
    uint64_t cross2_low = 0;
    carryless_multiply(x.low, h.low, &low_high, &low_low);
    carryless_multiply(x.high, h.high, &high_high, &high_low);
    carryless_multiply(x.low, h.high, &cross1_high, &cross1_low);
    carryless_multiply(x.high, h.low, &cross2_high, &cross2_low);

    // The 256-bit product as four words, word3 the most significant.
    uint64_t word0 = low_low;
    uint64_t word1 = low_high ^ cross1_low ^ cross2_low;
    uint64_t word2 = high_low ^ cross1_high ^ cross2_high;
    uint64_t word3 = high_high;

    // The shift left by one that the reversed bit order needs.
    word3 = (word3 << 1) | (word2 >> 63);
    word2 = (word2 << 1) | (word1 >> 63);
    word1 = (word1 << 1) | (word0 >> 63);
    word0 = word0 << 1;

    // Reduction: word1:word0 holds the coefficients of x^128 to x^255,
    // and x^128 = x^7 + x^2 + x + 1, so word1:word0 is added back
    // unshifted and shifted right by 1, 2 and 7. Those shifts move up to
    // seven bits out past bit 0; each is a term of x^256 or above, and
    // the first line reduces it once and adds it to word1 before the
    // shifts run.
    uint64_t folded = word1 ^ (word0 << 63) ^ (word0 << 62) ^ (word0 << 57);
    ghash_element result;
    result.high = word3 ^ folded ^ (folded >> 1) ^ (folded >> 2) ^ (folded >> 7);
    result.low = word2 ^ word0 ^ ((word0 >> 1) | (folded << 63)) ^ ((word0 >> 2) | (folded << 62)) ^
                 ((word0 >> 7) | (folded << 57));
    return result;
}

// Adds each block of data to the accumulator and multiplies by h. A last
// block shorter than GHASH_CLMUL_BLOCK is padded with zeros on the right,
// which is SP 800-38D §6.4's pad.
static ghash_element hash_data(ghash_element acc, ghash_element h, const uint8_t *data, size_t n) {
    size_t off = 0;
    while (off < n) {
        size_t take = n - off < GHASH_CLMUL_BLOCK ? n - off : GHASH_CLMUL_BLOCK;
        uint8_t block[GHASH_CLMUL_BLOCK] = {0};
        memcpy(block, data + off, take);
        acc.high ^= load_big_endian_64(block);
        acc.low ^= load_big_endian_64(&block[8]);
        acc = multiply(acc, h);
        off += take;
    }
    return acc;
}

void ghash_clmul(const uint8_t subkey[GHASH_CLMUL_BLOCK], const uint8_t *aad, size_t aad_len,
                 const uint8_t *ct, size_t n, uint8_t out[GHASH_CLMUL_BLOCK]) {
    ghash_element h = {load_big_endian_64(subkey), load_big_endian_64(&subkey[8])};
    ghash_element acc = {0, 0};
    acc = hash_data(acc, h, aad, aad_len);
    acc = hash_data(acc, h, ct, n);
    // The last block holds the two lengths in bits.
    acc.high ^= (uint64_t)aad_len * 8U;
    acc.low ^= (uint64_t)n * 8U;
    acc = multiply(acc, h);
    store_big_endian_64(out, acc.high);
    store_big_endian_64(&out[8], acc.low);
}

#endif // GHASH_CLMUL_INSTRUCTION
