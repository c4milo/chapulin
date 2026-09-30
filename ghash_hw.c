// AES=hw: GHASH on the carry-less multiply instruction. ghash_hw.h
// states the two contracts; this file implements them and nothing else.
//
// What the instruction computes. GHASH multiplies in GF(2^128)
// (SP 800-38D §6.3), and that multiply is a carry-less product of two
// 128-bit values followed by a reduction modulo x^128 + x^7 + x^2 + x + 1.
// The instruction computes the carry-less product of two 64-bit values.
// Every step below runs in vector registers: the products, their sums
// and the reduction, which runs on the instruction too. The functions
// that load a block, move halves and run the instruction differ between
// the two architectures; the multiply, the reduction and the loop over
// data are the same C on both.
//
// Bit order. SP 800-38D writes a block as a polynomial whose x^0
// coefficient is the most significant bit of byte 0. Reading the 16
// bytes big-endian into a 128-bit integer puts x^0 at integer bit 127 and
// x^127 at bit 0: the coefficients are reversed. The bytes are reversed
// in a vector register, so nothing here assumes host endianness.
//
// The subkey times x^-1. The carry-less product of two reversed 128-bit
// values a and b is the reversed product x * a * b, as a 256-bit value.
// So each multiply here takes H * x^-1 in place of H, and the x cancels.
// Reversed, H * x^-1 is H shifted left by one bit: the bit that moves out
// is the coefficient of x^-1, which is x^127 + x^6 + x + 1 modulo the
// field polynomial, so the shift adds that constant, which reads
// 0xc2000000000000000000000000000001 in this bit order, when the bit was
// set. A mask adds it, so no branch reads a bit of H. Every power of H
// here carries the same factor x^-1, and so does the product of two of
// them, because the multiply adds one x back.
//
// Karatsuba. Each 128-bit operand is two 64-bit halves, a = a1 * y^64 +
// a0, where y^k names integer bit k. The 256-bit product is a1 * b1 *
// y^128 + m * y^64 + a0 * b0, where the middle term m is
// (a0 + a1) * (b0 + b1) + a0 * b0 + a1 * b1. That is three carry-less
// multiplies where the schoolbook form takes four. Addition is
// exclusive-or, so the three products of several blocks add up before
// the middle term is formed, once for all of them.
//
// Reduction. Reversed, the field polynomial is P = y^128 + y^127 + y^126 +
// y^121 + 1, and adding w * P to the reversed product, for any w below
// y^128, adds a multiple of the field polynomial to the product itself.
// The low 128 bits of the reversed product hold the
// coefficients of x^255 down to x^128. Adding w * P for the 64-bit word w
// at the bottom clears that word, because P's lowest term is 1, and adds
// w * 0xc200000000000000 (y^63 + y^62 + y^57, P's terms from y^121 up,
// shifted down 64) one word higher and w two words higher. Two such steps
// clear the low 128 bits, each with one carry-less multiply, and the high
// 128 bits are then the reduced result, reversed. It is the reduction by
// the constant 0xc2 that Gueron and Kounavis describe for this bit order.
//
// The loop over data multiplies up to GHASH_PASS_BLOCKS blocks by powers
// of H before it reduces once (SP 800-38D §6.4 regrouped: the last block of
// a pass meets H, the one before it H^2, and the first, with the
// accumulator added, H^8). No block's product waits on another's, so a
// pass waits on one reduction where the one-block form waited on eight.
// Each call computes the powers it needs from H first, keeps them in
// ghash_state beside H, and wipes them with it when the call ends, the way
// gcm.c computes H for each call and wipes it.
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
// Timing. No line here branches on an operand or indexes memory with
// one: every step is a shift, a mask, an exclusive-or, a move between
// the halves of a register or the instruction. Whether the instruction
// takes the same number of cycles whatever its operands are is a claim
// neither macro makes, for the reason aes_hw.c gives for the AES
// instructions. CH_NATIVE_AES carries that claim for both: it is the
// build's statement that this part's AES instructions and its carry-less
// multiply run in constant time. ct.h states the terms, and only a
// -DCH_SUITE_AES_GCM build needs them, because under the three public keys
// INV-26 admits, the hash subkey is public too.
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
// one reduction where the one-block form waited on eight. Each loop over
// a pass's blocks carries #pragma GCC unroll 8, for the reason aes_hw.c
// gives, so the assertion holds the written-out count to this one.
#define GHASH_PASS_BLOCKS 8
_Static_assert(GHASH_PASS_BLOCKS == 8,
               "each #pragma GCC unroll below writes GHASH_PASS_BLOCKS out");

// The two 64-bit words of 0xc200000000000000: P's terms from y^121 up,
// shifted down 64, which the reduction multiplies by, and the low word
// of x^-1, whose high word is the same constant.
#define GHASH_REDUCTION_WORD 0xc200000000000000U
#define GHASH_INVERSE_X_LOW_WORD 0x1U

// One GF(2^128) element, or a carry-less product, in a vector register,
// reversed as the paragraph at the top says: lane 0 holds integer bits 0
// to 63, which are bytes 8 to 15 of a block read big-endian, and lane 1
// bits 64 to 127, bytes 0 to 7. A carry-less product of two 64-bit words
// fills both lanes the same way.
#ifdef GHASH_HW_ARM
typedef uint64x2_t ghash_vector;

// A block as an element. vld1q_u8 puts byte i in byte lane i, vrev64q_u8
// reverses the eight bytes of each half, and vextq_u64 swaps the halves,
// so the sixteen bytes end reversed.
static ghash_vector load_element(const uint8_t block[AES_BLOCK]) {
    uint64x2_t halves = vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block)));
    return vextq_u64(halves, halves, 1);
}

static void store_element(uint8_t block[AES_BLOCK], ghash_vector v) {
    vst1q_u8(block, vrev64q_u8(vreinterpretq_u8_u64(vextq_u64(v, v, 1))));
}

static ghash_vector xor_vector(ghash_vector a, ghash_vector b) {
    return veorq_u64(a, b);
}

// (v's lane 1, v's lane 0): the two halves exchanged.
static ghash_vector swap_halves(ghash_vector v) {
    return vextq_u64(v, v, 1);
}

// (0, v's lane 0): v shifted up 64 bits.
static ghash_vector low_half_up(ghash_vector v) {
    return vextq_u64(vdupq_n_u64(0), v, 1);
}

// (v's lane 1, 0): v shifted down 64 bits.
static ghash_vector high_half_down(ghash_vector v) {
    return vextq_u64(v, vdupq_n_u64(0), 1);
}

// (v's lane 0, 0): v with its high half cleared.
static ghash_vector low_half_only(ghash_vector v) {
    return vcombine_u64(vget_low_u64(v), vdup_n_u64(0));
}

// The carry-less product of a's lane 0 and b's lane 0, and of the two
// lanes 1.
static ghash_vector multiply_low_halves(ghash_vector a, ghash_vector b) {
    return vreinterpretq_u64_p128(vmull_p64(vgetq_lane_p64(vreinterpretq_p64_u64(a), 0),
                                            vgetq_lane_p64(vreinterpretq_p64_u64(b), 0)));
}

static ghash_vector multiply_high_halves(ghash_vector a, ghash_vector b) {
    return vreinterpretq_u64_p128(
        vmull_high_p64(vreinterpretq_p64_u64(a), vreinterpretq_p64_u64(b)));
}

// The vector whose lane 0 holds low and lane 1 high.
static ghash_vector vector_of(uint64_t low, uint64_t high) {
    return vcombine_u64(vcreate_u64(low), vcreate_u64(high));
}

// v * x^-1, the paragraph at the top: v shifted left one bit across both
// lanes, with x^-1 added when bit 127 moved out. The arithmetic shift of
// lane 1 by 63 spreads bit 127 into a mask of all ones or none.
static ghash_vector times_inverse_x(ghash_vector v) {
    ghash_vector carries = vshrq_n_u64(v, 63);
    ghash_vector shifted = vorrq_u64(vshlq_n_u64(v, 1), low_half_up(carries));
    ghash_vector top = vdupq_laneq_u64(v, 1);
    ghash_vector mask = vreinterpretq_u64_s64(vshrq_n_s64(vreinterpretq_s64_u64(top), 63));
    ghash_vector inverse_x = vector_of(GHASH_INVERSE_X_LOW_WORD, GHASH_REDUCTION_WORD);
    return veorq_u64(shifted, vandq_u64(mask, inverse_x));
}
#else
// The same on x86-64, with the same lanes. SSE2 has no byte shuffle, so
// the reversal swaps the bytes of each 16-bit word, then the words of
// each half, then the halves.
typedef __m128i ghash_vector;

static ghash_vector reverse_bytes(ghash_vector v) {
    ghash_vector swapped = _mm_or_si128(_mm_slli_epi16(v, 8), _mm_srli_epi16(v, 8));
    swapped = _mm_shufflehi_epi16(_mm_shufflelo_epi16(swapped, 0x1b), 0x1b);
    return _mm_shuffle_epi32(swapped, 0x4e);
}

static ghash_vector load_element(const uint8_t block[AES_BLOCK]) {
    return reverse_bytes(_mm_loadu_si128((const __m128i *)(const void *)block));
}

static void store_element(uint8_t block[AES_BLOCK], ghash_vector v) {
    _mm_storeu_si128((__m128i *)(void *)block, reverse_bytes(v));
}

static ghash_vector xor_vector(ghash_vector a, ghash_vector b) {
    return _mm_xor_si128(a, b);
}

static ghash_vector swap_halves(ghash_vector v) {
    return _mm_shuffle_epi32(v, 0x4e);
}

static ghash_vector low_half_up(ghash_vector v) {
    return _mm_slli_si128(v, 8);
}

static ghash_vector high_half_down(ghash_vector v) {
    return _mm_srli_si128(v, 8);
}

static ghash_vector low_half_only(ghash_vector v) {
    return _mm_move_epi64(v);
}

// Bit 0 of the immediate picks a's lane and bit 4 picks b's.
static ghash_vector multiply_low_halves(ghash_vector a, ghash_vector b) {
    return _mm_clmulepi64_si128(a, b, 0x00);
}

static ghash_vector multiply_high_halves(ghash_vector a, ghash_vector b) {
    return _mm_clmulepi64_si128(a, b, 0x11);
}

static ghash_vector vector_of(uint64_t low, uint64_t high) {
    return _mm_set_epi64x((long long)high, (long long)low);
}

// The arithmetic shift of the top 32-bit lane, copied into all four,
// spreads bit 127 into the mask.
static ghash_vector times_inverse_x(ghash_vector v) {
    ghash_vector carries = _mm_srli_epi64(v, 63);
    ghash_vector shifted = _mm_or_si128(_mm_slli_epi64(v, 1), low_half_up(carries));
    ghash_vector mask = _mm_srai_epi32(_mm_shuffle_epi32(v, 0xff), 31);
    ghash_vector inverse_x = vector_of(GHASH_INVERSE_X_LOW_WORD, GHASH_REDUCTION_WORD);
    return _mm_xor_si128(shifted, _mm_and_si128(mask, inverse_x));
}
#endif

// The three products of one or more pairs of elements, added up before
// the middle term is formed: low sums the products of the two low halves,
// high those of the two high halves, and middle those of each element's
// two halves added together.
typedef struct {
    ghash_vector low;
    ghash_vector high;
    ghash_vector middle;
} ghash_sums;

// Everything the multiplies compute from the hash subkey, in one object
// so that one wipe at the end of an entry clears all of it. powers comes
// last, so an entry that computed only some of them wipes up to the last
// one it wrote.
typedef struct {
    ghash_vector subkey; // the hash subkey H
    ghash_vector acc;    // the accumulator
    ghash_sums sums;     // the products a multiply or a pass adds up, before reduce
    ghash_vector powers[GHASH_PASS_BLOCKS]; // powers[i] holds H^(i + 1) * x^-1
} ghash_state;

// powers[i], read from s through a volatile lvalue, so the compiler reads
// the state each time a multiply takes a power rather than holding the
// eight powers in registers across a pass. Held there, they did not fit
// beside a pass's blocks: clang and gcc both copied some of them, or their
// halves added, to stack slots of their own, which the wipe of s does not
// clear, and test/ghash_equiv_residue.h found the copies.
static ghash_vector power_at(const ghash_state *s, size_t i) {
    const volatile ghash_vector *power = &s->powers[i];
    return *power;
}

// sums = the three products of x and power, or sums += them. The middle
// product takes each operand's two halves added, which x ^ swap(x) holds
// in both lanes.
static void start_sums(ghash_sums *sums, ghash_vector x, ghash_vector power) {
    sums->low = multiply_low_halves(x, power);
    sums->high = multiply_high_halves(x, power);
    sums->middle =
        multiply_low_halves(xor_vector(x, swap_halves(x)), xor_vector(power, swap_halves(power)));
}

static void add_products(ghash_sums *sums, ghash_vector x, ghash_vector power) {
    ghash_sums products;
    start_sums(&products, x, power);
    sums->low = xor_vector(sums->low, products.low);
    sums->high = xor_vector(sums->high, products.high);
    sums->middle = xor_vector(sums->middle, products.middle);
}

// The sum of products modulo the field polynomial, the paragraphs at the
// top. The product's four 64-bit words, w0 the lowest, come from the
// three sums, with the middle term between the other two:
//
//   w0 = low's lane 0            w2 = high's lane 0 + middle's lane 1
//   w1 = low's lane 1 + middle's lane 0          w3 = high's lane 1
//
// The first step clears w0. first holds the new w1 in lane 0 and, in
// lane 1, what the step adds to w2: w0 itself, plus the high half of w0
// times 0xc200000000000000, whose low half lane 0 takes. w0 is low's lane
// 0 alone, so that multiply need not wait for the middle term. The second
// step clears the new w1 the same way, and what is left is w2 and w3.
static ghash_vector reduce(const ghash_sums *sums) {
    ghash_vector constant = vector_of(GHASH_REDUCTION_WORD, 0);
    ghash_vector middle = xor_vector(sums->middle, xor_vector(sums->low, sums->high));
    ghash_vector first = xor_vector(xor_vector(swap_halves(sums->low), low_half_only(middle)),
                                    multiply_low_halves(sums->low, constant));
    ghash_vector upper = xor_vector(sums->high, high_half_down(middle));
    ghash_vector second = xor_vector(swap_halves(first), multiply_low_halves(first, constant));
    return xor_vector(upper, second);
}

// s->powers[i] holds H^(i + 1) * x^-1 for each i below count, which is at
// least 1 and at most GHASH_PASS_BLOCKS. H^(i + 1) is H^half times
// H^(i + 1 - half), half the largest power of two at or below i, so the
// seven multiplies run in three rounds, H^2, then H^3 and H^4, then H^5
// to H^8, and no multiply waits on another of its round.
static void compute_powers(ghash_state *s, size_t count) {
    s->powers[0] = times_inverse_x(s->subkey);
    for (size_t i = 1; i < count; i++) {
        size_t half = 1;
        while (2 * half <= i) {
            half *= 2;
        }
        start_sums(&s->sums, power_at(s, half - 1), power_at(s, i - half));
        s->powers[i] = reduce(&s->sums);
    }
}

// SP 800-38D §6.4 over count whole blocks at data, 1 <= count <=
// GHASH_PASS_BLOCKS: each block is added to the accumulator and the
// accumulator multiplied by H, which comes to
//
//   acc = (acc + X_1) * H^count + X_2 * H^(count - 1) + ... + X_count * H.
//
// No block's product waits on another's, and their sum takes one
// reduction. The first block's products are added last: they are the
// only ones that wait on the last pass's reduction, so the products of
// the other blocks can run while it finishes.
static void hash_blocks(ghash_state *s, const uint8_t *data, size_t count) {
    ghash_vector first = xor_vector(load_element(data), s->acc);
    if (count == 1) {
        start_sums(&s->sums, first, power_at(s, 0));
    } else {
        start_sums(&s->sums, load_element(&data[AES_BLOCK]), power_at(s, count - 2));
        for (size_t j = 2; j < count; j++) {
            add_products(&s->sums, load_element(&data[j * AES_BLOCK]), power_at(s, count - 1 - j));
        }
        add_products(&s->sums, first, power_at(s, count - 1));
    }
    s->acc = reduce(&s->sums);
}

// hash_blocks over GHASH_PASS_BLOCKS blocks, with the count written out
// so the compiler unrolls the loop.
static void hash_pass(ghash_state *s, const uint8_t *data) {
    start_sums(&s->sums, load_element(&data[AES_BLOCK]), power_at(s, GHASH_PASS_BLOCKS - 2));
#pragma GCC unroll 8
    for (size_t j = 2; j < GHASH_PASS_BLOCKS; j++) {
        add_products(&s->sums, load_element(&data[j * AES_BLOCK]),
                     power_at(s, GHASH_PASS_BLOCKS - 1 - j));
    }
    add_products(&s->sums, xor_vector(load_element(data), s->acc),
                 power_at(s, GHASH_PASS_BLOCKS - 1));
    s->acc = reduce(&s->sums);
}

void gcm_multiply_by_subkey_hw(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK]) {
    ghash_state s;
    s.subkey = load_element(subkey);
    s.acc = load_element(acc);
    compute_powers(&s, 1);
    start_sums(&s.sums, s.acc, s.powers[0]);
    s.acc = reduce(&s.sums);
    store_element(acc, s.acc);
    // s holds the hash subkey itself, H * x^-1 and the unreduced product,
    // so the frame would hand a later caller the subkey. gcm.c's multiply
    // wipes its running multiple for the same reason. This entry computes
    // one power, so the wipe stops after it.
    ct_wipe(&s, offsetof(ghash_state, powers) + sizeof s.powers[0]);
}

void gcm_hash_data_hw(uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *data,
                      size_t n) {
    ghash_state s;
    s.subkey = load_element(subkey);
    s.acc = load_element(acc);
    size_t whole = n / AES_BLOCK;
    // One power for each block of the longest pass, and H alone when the
    // data is one partial block or none.
    size_t powers = whole < GHASH_PASS_BLOCKS ? whole : GHASH_PASS_BLOCKS;
    if (powers == 0) {
        powers = 1;
    }
    compute_powers(&s, powers);
    size_t done = 0;
    while (whole - done >= GHASH_PASS_BLOCKS) {
        hash_pass(&s, &data[done * AES_BLOCK]);
        done += GHASH_PASS_BLOCKS;
    }
    if (done < whole) {
        hash_blocks(&s, &data[done * AES_BLOCK], whole - done);
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
    store_element(acc, s.acc);
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
