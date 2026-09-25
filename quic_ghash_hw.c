// AES=hw: GHASH on the carry-less multiply instruction. quic_ghash_hw.h
// states the two contracts; this file implements them and nothing else.
//
// What the instruction computes. GHASH multiplies in GF(2^128)
// (SP 800-38D §6.3), and that multiply is a carry-less product of two
// 128-bit values followed by a reduction modulo x^128 + x^7 + x^2 + x + 1.
// The instruction computes the carry-less product of two 64-bit values,
// so one block takes four of them: each operand splits into two halves,
// and every half of one meets every half of the other. The reduction
// runs in plain 64-bit shifts and exclusive-ors. Only the one function
// that runs the instruction differs between the two architectures; the
// four products, the shift and the reduction are the same C on both.
//
// It is the plain one-multiply-per-block form. It keeps no table of the
// powers of H, so it does not overlap the multiplies of several blocks,
// and it computes four products per block where Karatsuba's form needs
// three. Each of those is more code to audit, and neither was measured
// against this form (docs/quic.md, "What the AES axis costs in time,
// measured").
//
// Two instruction sets, and the compiler picks between them at build
// time, as it does for quic_aes_hw.c:
//
//   __ARM_FEATURE_AES  PMULL, through vmull_p64 in <arm_neon.h>. The Arm
//                      C Language Extensions put the 64-bit PMULL in the
//                      AES extension, so the macro that gives
//                      quic_aes_hw.c its AES instructions gives this file
//                      its multiply.
//   __PCLMUL__         PCLMULQDQ, through _mm_clmulepi64_si128 in
//                      <wmmintrin.h>, on x86-64. x86-64 names it apart
//                      from AES-NI, so the build needs -mpclmul beside
//                      -maes, and the Makefile's AES_HW_PROBE asks for
//                      both.
//
// A build that defines neither gets the #error below rather than a
// silent fall back to quic_gcm.c's portable multiply, because AES=hw is a
// statement about what the object contains. quic_aes_hw.c states why
// nothing here probes a CPU at run time.
//
// Bit order. SP 800-38D writes a block as a polynomial whose x^0
// coefficient is the most significant bit of byte 0. Reading the 16
// bytes big-endian into a 128-bit integer therefore puts x^0 at integer
// bit 127 and x^127 at bit 0: the coefficients are reversed. The
// carry-less product of two reversed values is the reversed product
// shifted right by one bit, so the code shifts it left by one before it
// reduces. The reduction is Gueron and Kounavis's for this bit order
// (Intel, "Carry-Less Multiplication Instruction and its Usage for
// Computing the GCM Mode", Algorithm 5). The bytes are read and written
// one at a time, so nothing here assumes host endianness.
//
// Timing. No line here branches on an operand or indexes memory with
// one: every step is a shift, an exclusive-or or the instruction.
// Whether the instruction takes the same number of cycles whatever its
// operands are is a claim neither macro makes, for the reason
// quic_aes_hw.c gives for the AES instructions. CH_NATIVE_AES carries
// that claim for both: it is the build's statement that this part's AES
// instructions and its carry-less multiply run in constant time. ct.h
// states the terms, and only a -DCH_SUITE_AES_GCM build needs them,
// because under the three public keys INV-26 admits, the hash subkey is
// public too.
//
// CBMC cannot read an intrinsic, so the proofs stay on quic_gcm.c's
// portable multiply and test/ghash_equiv_test.c holds this file to it:
// it runs both multiplies, both loops over data and both whole AEADs
// over the same inputs and compares byte for byte.
#include "quic_ghash_hw.h"

#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#ifdef CH_AES_HW

#include <stddef.h>
#include <string.h>

#include "ct.h"

#ifdef __ARM_FEATURE_AES
#include <arm_neon.h>

// high:low = the 128-bit carry-less product of a and b, on PMULL.
static void carryless_multiply(uint64_t a, uint64_t b, uint64_t *high, uint64_t *low) {
    uint64x2_t product = vreinterpretq_u64_p128(vmull_p64((poly64_t)a, (poly64_t)b));
    *low = vgetq_lane_u64(product, 0);
    *high = vgetq_lane_u64(product, 1);
}
#elif defined(__PCLMUL__)
#include <wmmintrin.h>

// high:low = the 128-bit carry-less product of a and b, on PCLMULQDQ.
// The immediate 0x00 multiplies the low 64-bit lane of one operand by the
// low lane of the other.
static void carryless_multiply(uint64_t a, uint64_t b, uint64_t *high, uint64_t *low) {
    __m128i product = _mm_clmulepi64_si128(_mm_cvtsi64_si128((long long)a),
                                           _mm_cvtsi64_si128((long long)b), 0x00);
    *low = (uint64_t)_mm_cvtsi128_si64(product);
    *high = (uint64_t)_mm_cvtsi128_si64(_mm_unpackhi_epi64(product, product));
}
#else
#error                                                                                             \
    "AES=hw needs the carry-less multiply: compile with -march=armv8-a+crypto or -maes -mpclmul, or build AES=soft"
#endif

// One GF(2^128) element as a 128-bit integer in two words: high holds
// bytes 0 to 7 of the block read big-endian, low holds bytes 8 to 15.
typedef struct {
    uint64_t high;
    uint64_t low;
} ghash_element;

// Everything the multiplies compute from the hash subkey, in one object
// so that one wipe at the end of an entry clears all of it.
typedef struct {
    ghash_element subkey; // the hash subkey H
    ghash_element acc;    // the accumulator
    uint64_t product[4];  // acc * subkey before the reduction, product[3] the most significant
} ghash_state;

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

static void load_element(ghash_element *e, const uint8_t block[AES_BLOCK]) {
    e->high = load_big_endian_64(block);
    e->low = load_big_endian_64(&block[8]);
}

static void store_element(uint8_t block[AES_BLOCK], const ghash_element *e) {
    store_big_endian_64(block, e->high);
    store_big_endian_64(&block[8], e->low);
}

// s->product = s->acc * s->subkey, carry-less, shifted left by the one
// bit the reversed bit order needs.
static void multiply_carryless(ghash_state *s) {
    uint64_t low_high = 0;
    uint64_t low_low = 0;
    uint64_t high_high = 0;
    uint64_t high_low = 0;
    uint64_t cross1_high = 0;
    uint64_t cross1_low = 0;
    uint64_t cross2_high = 0;
    uint64_t cross2_low = 0;
    carryless_multiply(s->acc.low, s->subkey.low, &low_high, &low_low);
    carryless_multiply(s->acc.high, s->subkey.high, &high_high, &high_low);
    carryless_multiply(s->acc.low, s->subkey.high, &cross1_high, &cross1_low);
    carryless_multiply(s->acc.high, s->subkey.low, &cross2_high, &cross2_low);

    // The low halves' product fills the two low words and the high
    // halves' product the two high words. Each cross product covers the
    // middle two.
    uint64_t word0 = low_low;
    uint64_t word1 = low_high ^ cross1_low ^ cross2_low;
    uint64_t word2 = high_low ^ cross1_high ^ cross2_high;
    uint64_t word3 = high_high;

    s->product[3] = (word3 << 1) | (word2 >> 63);
    s->product[2] = (word2 << 1) | (word1 >> 63);
    s->product[1] = (word1 << 1) | (word0 >> 63);
    s->product[0] = word0 << 1;
}

// s->acc = s->product modulo x^128 + x^7 + x^2 + x + 1. product[3] and
// product[2] hold the coefficients of x^0 to x^127, and product[1] and
// product[0], the upper half, those of x^128 to x^255. Since
// x^128 = x^7 + x^2 + x + 1, the upper half is added to the lower one
// unshifted and shifted right by 1, 2 and 7, which multiplies it by x,
// x^2 and x^7 in this bit order. Those shifts move up to seven bits out
// past bit 0 of product[0]. Each such bit is a term of x^128 or above
// again, so the first line reduces those bits once and adds them to
// upper_high before the shifts run. They reduce to terms below x^14, so
// nothing moves out a second time.
static void reduce(ghash_state *s) {
    uint64_t upper_low = s->product[0];
    uint64_t upper_high = s->product[1] ^ (upper_low << 63) ^ (upper_low << 62) ^ (upper_low << 57);
    s->acc.high =
        s->product[3] ^ upper_high ^ (upper_high >> 1) ^ (upper_high >> 2) ^ (upper_high >> 7);
    s->acc.low = s->product[2] ^ upper_low ^ ((upper_low >> 1) | (upper_high << 63)) ^
                 ((upper_low >> 2) | (upper_high << 62)) ^ ((upper_low >> 7) | (upper_high << 57));
}

// s->acc = s->acc * s->subkey in GF(2^128).
static void multiply_by_subkey(ghash_state *s) {
    multiply_carryless(s);
    reduce(s);
}

void gcm_multiply_by_subkey_hw(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK]) {
    ghash_state s;
    load_element(&s.subkey, subkey);
    load_element(&s.acc, acc);
    multiply_by_subkey(&s);
    store_element(acc, &s.acc);
    // s holds the hash subkey itself and the unreduced product, so the
    // frame would hand a later caller the subkey. quic_gcm.c's multiply
    // wipes its running multiple for the same reason.
    ct_wipe(&s, sizeof s);
}

void gcm_hash_data_hw(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *data,
                      size_t n) {
    ghash_state s;
    load_element(&s.subkey, subkey);
    load_element(&s.acc, acc);
    size_t off = 0;
    while (off < n) {
        size_t take = n - off < AES_BLOCK ? n - off : AES_BLOCK;
        // Zero first, then the bytes there are, which leaves SP 800-38D
        // §6.4's pad on a last block shorter than AES_BLOCK. quic_gcm.c's
        // hash_data pads the same way.
        uint8_t block[AES_BLOCK];
        memset(block, 0, AES_BLOCK);
        memcpy(block, data + off, take);
        s.acc.high ^= load_big_endian_64(block);
        s.acc.low ^= load_big_endian_64(&block[8]);
        multiply_by_subkey(&s);
        off += take;
    }
    store_element(acc, &s.acc);
    // Once per call rather than once per block: s is the one object the
    // loop writes that holds the subkey, and a wipe inside the loop would
    // run per block for no further gain. block holds bytes of the data the
    // caller passed, which is associated data or ciphertext.
    ct_wipe(&s, sizeof s);
}

#endif // CH_AES_HW
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
