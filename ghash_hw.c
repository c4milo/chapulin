// AES=hw: GHASH on the carry-less multiply instruction. ghash_hw.h
// states the two contracts; this file implements them and nothing else.
//
// What the instruction computes. GHASH multiplies in GF(2^128)
// (SP 800-38D §6.3), and that multiply is a carry-less product of two
// 128-bit values followed by a reduction modulo x^128 + x^7 + x^2 + x + 1.
// The instruction computes the carry-less product of two 64-bit values,
// so one block takes four of them: each operand splits into two halves,
// and every half of one meets every half of the other. The reduction
// runs in plain 64-bit shifts and exclusive-ors. The functions that move
// an element into a vector register and run the four products differ
// between the two architectures; the sums, the shift, the reduction and
// the loop over data are the same C on both.
//
// The loop over data multiplies up to GHASH_PASS_BLOCKS blocks by powers
// of H before it reduces once (SP 800-38D §6.4 regrouped: the last block of
// a pass meets H, the one before it H^2, and the first, with the
// accumulator added, H^8). No block's product waits on another's, so a
// pass waits on one reduction where the one-block form waited on eight.
// Each call computes the powers it needs from H first, keeps them in
// ghash_state beside H, and wipes them with it when the call ends, the way
// gcm.c computes H for each call and wipes it. It computes four products
// per block where Karatsuba's form needs three; that form is more code to
// audit and was not measured against this one.
//
// Two instruction sets, and the compiler picks between them at build
// time, as it does for aes_hw.c:
//
//   __ARM_FEATURE_AES  PMULL, through vmull_p64 in <arm_neon.h>. The Arm
//                      C Language Extensions put the 64-bit PMULL in the
//                      AES extension, so the macro that gives
//                      aes_hw.c its AES instructions gives this file
//                      its multiply.
//   __PCLMUL__         PCLMULQDQ, through _mm_clmulepi64_si128 in
//                      <wmmintrin.h>, on x86-64. x86-64 names it apart
//                      from AES-NI, so the build needs -mpclmul beside
//                      -maes, and the Makefile's AES_HW_PROBE asks for
//                      both.
//
// A build that defines neither gets the #error below rather than a
// silent fall back to gcm.c's portable multiply, because AES=hw is a
// statement about what the object contains. aes_hw.c states why
// nothing here probes a CPU at run time.
//
// AES=runtime compiles this file with no instruction flag, as it compiles
// aes_hw.c: the architecture picks the instruction, and the pragma below
// puts the target attribute that turns it on onto each function in this
// file and on no function outside it. gcm.c calls this file only for a
// schedule the AES instructions run (aes_schedule.h), so a session whose
// caller's probe found no instructions runs no carry-less multiply.
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
// aes_hw.c gives for the AES instructions. CH_NATIVE_AES carries
// that claim for both: it is the build's statement that this part's AES
// instructions and its carry-less multiply run in constant time. ct.h
// states the terms, and only a -DCH_SUITE_AES_GCM build needs them,
// because under the three public keys INV-26 admits, the hash subkey is
// public too.
//
// CBMC cannot read an intrinsic, so the proofs stay on gcm.c's
// portable multiply and test/ghash_equiv_test.c holds this file to it:
// it runs both multiplies, both loops over data and both whole AEADs
// over the same inputs and compares byte for byte.
#include "ghash_hw.h"

#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#if defined(CH_AES_HW) || defined(CH_AES_RUNTIME)

#include <stddef.h>
#include <string.h>

#include "ct.h"

// Which instruction the multiply below takes: PMULL where GHASH_HW_ARM is
// defined, and PCLMULQDQ where it is not. Under AES=hw the build's flags
// say which, and under AES=runtime the architecture does, because no flag
// turns the instruction on.
#ifdef CH_AES_RUNTIME
#ifdef __aarch64__
#define GHASH_HW_ARM
#elif !defined(__x86_64__)
#error "AES=runtime needs an arm64 or x86-64 target, whose carry-less multiply it can run"
#endif
#elif defined(__ARM_FEATURE_AES)
#define GHASH_HW_ARM
#elif !defined(__PCLMUL__)
#error                                                                                             \
    "AES=hw needs the carry-less multiply: compile with -march=armv8-a+crypto or -maes -mpclmul, or build AES=soft"
#endif

#ifdef GHASH_HW_ARM
#include <arm_neon.h>
#else
#include <wmmintrin.h>
#endif

// Under AES=runtime, every function from here to the pop at the end of
// this file carries the target attribute that turns the instruction on:
// "+aes", the Arm AES extension, which the Arm C Language Extensions give
// the 64-bit PMULL, or "pclmul", x86-64's PCLMULQDQ. aes_hw.c states how
// each compiler's pragma applies it.
#ifdef CH_AES_RUNTIME
#ifdef __clang__
#ifdef GHASH_HW_ARM
#pragma clang attribute push(__attribute__((target("+aes"))), apply_to = function)
#else
#pragma clang attribute push(__attribute__((target("pclmul"))), apply_to = function)
#endif
#else
#pragma GCC push_options
#ifdef GHASH_HW_ARM
#pragma GCC target("+aes")
#else
#pragma GCC target("pclmul")
#endif
#endif
#endif

// How many blocks gcm_hash_data_hw multiplies before one reduction, and
// so how many powers of the hash subkey it computes first. The eight
// blocks' products do not depend on each other, and each pass waits on
// one reduction where the one-block form waited on eight.
#define GHASH_PASS_BLOCKS 8

// One GF(2^128) element as a 128-bit integer in two words: high holds
// bytes 0 to 7 of the block read big-endian, low holds bytes 8 to 15.
typedef struct {
    uint64_t high;
    uint64_t low;
} ghash_element;

// An element in a vector register: lane 0 holds its high word and lane 1
// its low word. A carry-less product in a vector holds bits 0 to 63 of
// the 128-bit product in lane 0 and bits 64 to 127 in lane 1.
#ifdef GHASH_HW_ARM
typedef uint64x2_t ghash_vector;
#else
typedef __m128i ghash_vector;
#endif

// The carry-less products of one or more pairs of elements, added up
// before the reduction: low sums the products of the two low words, high
// those of the two high words, and cross those of each high word with
// the other element's low word.
typedef struct {
    ghash_vector low;
    ghash_vector high;
    ghash_vector cross;
} ghash_sums;

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

#ifdef GHASH_HW_ARM
static ghash_vector element_vector(const ghash_element *e) {
    return vcombine_u64(vcreate_u64(e->high), vcreate_u64(e->low));
}

// A block of data as an element. vld1q_u8 puts byte i in byte lane i,
// and vrev64q_u8 reverses the eight bytes of each half, so each 64-bit
// lane reads its half big-endian.
static ghash_vector block_vector(const uint8_t block[AES_BLOCK]) {
    return vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block)));
}

static ghash_vector xor_vector(ghash_vector a, ghash_vector b) {
    return veorq_u64(a, b);
}

static ghash_vector zero_vector(void) {
    return vdupq_n_u64(0);
}

static uint64_t product_low(ghash_vector v) {
    return vgetq_lane_u64(v, 0);
}

static uint64_t product_high(ghash_vector v) {
    return vgetq_lane_u64(v, 1);
}

// sums += a * b, carry-less, on PMULL. vmull_p64 multiplies lane 0 of
// each operand, the high words, and vmull_high_p64 lane 1 of each, the
// low words. a_swapped holds a's low word in lane 0 and its high word in
// lane 1, which gives the two cross products.
static void multiply_accumulate(ghash_sums *sums, ghash_vector a, ghash_vector b) {
    poly64x2_t pa = vreinterpretq_p64_u64(a);
    poly64x2_t pb = vreinterpretq_p64_u64(b);
    poly64x2_t a_swapped = vreinterpretq_p64_u64(vextq_u64(a, a, 1));
    ghash_vector highs =
        vreinterpretq_u64_p128(vmull_p64(vgetq_lane_p64(pa, 0), vgetq_lane_p64(pb, 0)));
    ghash_vector lows = vreinterpretq_u64_p128(vmull_high_p64(pa, pb));
    ghash_vector low_high =
        vreinterpretq_u64_p128(vmull_p64(vgetq_lane_p64(a_swapped, 0), vgetq_lane_p64(pb, 0)));
    ghash_vector high_low = vreinterpretq_u64_p128(vmull_high_p64(a_swapped, pb));
    sums->high = veorq_u64(sums->high, highs);
    sums->low = veorq_u64(sums->low, lows);
    sums->cross = veorq_u64(sums->cross, veorq_u64(low_high, high_low));
}
#else
// The same seven on x86-64, with the same lanes.
static ghash_vector element_vector(const ghash_element *e) {
    return _mm_set_epi64x((long long)e->low, (long long)e->high);
}

// SSE2 has no byte shuffle, so a block goes through its two big-endian
// words.
static ghash_vector block_vector(const uint8_t block[AES_BLOCK]) {
    ghash_element e;
    load_element(&e, block);
    return element_vector(&e);
}

static ghash_vector xor_vector(ghash_vector a, ghash_vector b) {
    return _mm_xor_si128(a, b);
}

static ghash_vector zero_vector(void) {
    return _mm_setzero_si128();
}

static uint64_t product_low(ghash_vector v) {
    return (uint64_t)_mm_cvtsi128_si64(v);
}

static uint64_t product_high(ghash_vector v) {
    return (uint64_t)_mm_cvtsi128_si64(_mm_unpackhi_epi64(v, v));
}

// Bit 0 of the immediate picks a's lane and bit 4 picks b's.
static void multiply_accumulate(ghash_sums *sums, ghash_vector a, ghash_vector b) {
    sums->high = _mm_xor_si128(sums->high, _mm_clmulepi64_si128(a, b, 0x00));
    sums->low = _mm_xor_si128(sums->low, _mm_clmulepi64_si128(a, b, 0x11));
    sums->cross = _mm_xor_si128(sums->cross, _mm_xor_si128(_mm_clmulepi64_si128(a, b, 0x10),
                                                           _mm_clmulepi64_si128(a, b, 0x01)));
}
#endif

// Everything the multiplies compute from the hash subkey, in one object
// so that one wipe at the end of an entry clears all of it. powers comes
// last, so an entry that computed only some of them wipes up to the last
// one it wrote.
typedef struct {
    ghash_element subkey; // the hash subkey H
    ghash_element acc;    // the accumulator
    ghash_element power;  // the power of H compute_powers is computing
    uint64_t product[4];  // a sum of products before the reduction, product[3] the most significant
    ghash_sums sums;      // the products a multiply or a pass adds up, before product_of
    ghash_vector powers[GHASH_PASS_BLOCKS]; // powers[i] = H^(i + 1)
} ghash_state;

// s->sums = 0, the start of a sum of products.
static void clear_sums(ghash_state *s) {
    s->sums.low = zero_vector();
    s->sums.high = zero_vector();
    s->sums.cross = zero_vector();
}

// s->product = the sum s->sums holds as one 256-bit value, shifted left by
// the one bit the reversed bit order needs. The low words' products fill
// the two low words and the high words' products the two high words, and
// the cross products cover the middle two. The shift and the reduction
// below both distribute over exclusive-or, so a sum of products reduces
// to the sum of the reduced products.
static void product_of(ghash_state *s) {
    uint64_t word0 = product_low(s->sums.low);
    uint64_t word1 = product_high(s->sums.low) ^ product_low(s->sums.cross);
    uint64_t word2 = product_low(s->sums.high) ^ product_high(s->sums.cross);
    uint64_t word3 = product_high(s->sums.high);

    s->product[3] = (word3 << 1) | (word2 >> 63);
    s->product[2] = (word2 << 1) | (word1 >> 63);
    s->product[1] = (word1 << 1) | (word0 >> 63);
    s->product[0] = word0 << 1;
}

// *out = s->product modulo x^128 + x^7 + x^2 + x + 1. product[3] and
// product[2] hold the coefficients of x^0 to x^127, and product[1] and
// product[0], the upper half, those of x^128 to x^255. Since
// x^128 = x^7 + x^2 + x + 1, the upper half is added to the lower one
// unshifted and shifted right by 1, 2 and 7, which multiplies it by x,
// x^2 and x^7 in this bit order. Those shifts move up to seven bits out
// past bit 0 of product[0]. Each such bit is a term of x^128 or above
// again, so the first line reduces those bits once and adds them to
// upper_high before the shifts run. They reduce to terms below x^14, so
// nothing moves out a second time.
static void reduce(const ghash_state *s, ghash_element *out) {
    uint64_t upper_low = s->product[0];
    uint64_t upper_high = s->product[1] ^ (upper_low << 63) ^ (upper_low << 62) ^ (upper_low << 57);
    out->high =
        s->product[3] ^ upper_high ^ (upper_high >> 1) ^ (upper_high >> 2) ^ (upper_high >> 7);
    out->low = s->product[2] ^ upper_low ^ ((upper_low >> 1) | (upper_high << 63)) ^
               ((upper_low >> 2) | (upper_high << 62)) ^ ((upper_low >> 7) | (upper_high << 57));
}

// *out = a * b in GF(2^128).
static void multiply(ghash_state *s, ghash_vector a, ghash_vector b, ghash_element *out) {
    clear_sums(s);
    multiply_accumulate(&s->sums, a, b);
    product_of(s);
    reduce(s, out);
}

// s->powers[i] = H^(i + 1) for each i below count, which is at least 1
// and at most GHASH_PASS_BLOCKS. H^(i + 1) is H^half times
// H^(i + 1 - half), half the largest power of two at or below i, so the
// seven multiplies run in three rounds, H^2, then H^3 and H^4, then H^5
// to H^8, and no multiply waits on another of its round.
static void compute_powers(ghash_state *s, size_t count) {
    s->powers[0] = element_vector(&s->subkey);
    for (size_t i = 1; i < count; i++) {
        size_t half = 1;
        while (2 * half <= i) {
            half *= 2;
        }
        multiply(s, s->powers[half - 1], s->powers[i - half], &s->power);
        s->powers[i] = element_vector(&s->power);
    }
}

// SP 800-38D §6.4 over count whole blocks at data, 1 <= count <=
// GHASH_PASS_BLOCKS: each block is added to the accumulator and the
// accumulator multiplied by H, which comes to
//
//   acc = (acc + X_1) * H^count + X_2 * H^(count - 1) + ... + X_count * H.
//
// No block's product waits on another's, and their sum takes one
// reduction.
static void hash_blocks(ghash_state *s, const uint8_t *data, size_t count) {
    clear_sums(s);
    ghash_vector first = xor_vector(block_vector(data), element_vector(&s->acc));
    multiply_accumulate(&s->sums, first, s->powers[count - 1]);
    for (size_t j = 1; j < count; j++) {
        multiply_accumulate(&s->sums, block_vector(&data[j * AES_BLOCK]), s->powers[count - 1 - j]);
    }
    product_of(s);
    reduce(s, &s->acc);
}

void gcm_multiply_by_subkey_hw(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK]) {
    ghash_state s;
    load_element(&s.subkey, subkey);
    load_element(&s.acc, acc);
    multiply(&s, element_vector(&s.acc), element_vector(&s.subkey), &s.acc);
    store_element(acc, &s.acc);
    // s holds the hash subkey itself and the unreduced product, so the
    // frame would hand a later caller the subkey. gcm.c's multiply
    // wipes its running multiple for the same reason. This entry computes
    // no power, so the wipe stops where powers begins.
    ct_wipe(&s, offsetof(ghash_state, powers));
}

void gcm_hash_data_hw(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *data,
                      size_t n) {
    ghash_state s;
    load_element(&s.subkey, subkey);
    load_element(&s.acc, acc);
    size_t whole = n / AES_BLOCK;
    // One power for each block of the longest pass, and H alone when the
    // data is one partial block or none.
    size_t powers = whole < GHASH_PASS_BLOCKS ? whole : GHASH_PASS_BLOCKS;
    if (powers == 0) {
        powers = 1;
    }
    compute_powers(&s, powers);
    size_t done = 0;
    while (done < whole) {
        size_t count = whole - done < GHASH_PASS_BLOCKS ? whole - done : GHASH_PASS_BLOCKS;
        hash_blocks(&s, &data[done * AES_BLOCK], count);
        done += count;
    }
    size_t rest = n - whole * AES_BLOCK;
    if (rest > 0) {
        // Zero first, then the bytes there are, which leaves SP 800-38D
        // §6.4's pad on the last block. gcm.c's hash_data pads the same
        // way.
        uint8_t block[AES_BLOCK];
        memset(block, 0, AES_BLOCK);
        memcpy(block, &data[whole * AES_BLOCK], rest);
        hash_blocks(&s, block, 1);
    }
    store_element(acc, &s.acc);
    // Once per call rather than once per pass: s is the one object the
    // loop writes that holds the subkey and its powers, and a wipe inside
    // the loop would run per pass for no further gain. It covers every
    // power this call computed. block holds bytes of the data the caller
    // passed, which is associated data or ciphertext.
    ct_wipe(&s, offsetof(ghash_state, powers) + powers * sizeof s.powers[0]);
}

#ifdef CH_AES_RUNTIME
#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif
#endif

#endif // CH_AES_HW || CH_AES_RUNTIME
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
