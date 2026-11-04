// GHASH's multiply on the carry-less multiply instruction, in vector
// registers: the element layout, the three products of Karatsuba's form,
// the reduction, the powers of the hash subkey and the loop over a pass of
// blocks. ghash_hw.c's two entries run them alone, and gcm_hw.c's one-pass
// loops run them beside counter mode's AES rounds. Every function here is
// static inline, so each of those files compiles its own copy under its own
// target, and nothing here is an entry of the object.
//
// What the instruction computes. GHASH multiplies in GF(2^128)
// (SP 800-38D §6.3), and that multiply is a carry-less product of two
// 128-bit values followed by a reduction modulo x^128 + x^7 + x^2 + x + 1.
// The instruction computes the carry-less product of two 64-bit values.
// Every step below runs in vector registers: the products, their sums
// and the reduction, which runs on the instruction too. The functions
// that load a block, move halves and run the instruction differ between
// the two architectures; the multiply, the reduction and the loop over a
// pass are the same C on both.
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
// The low 128 bits of the reversed product hold the coefficients of x^255
// down to x^128. Adding w * P for the 64-bit word w at the bottom clears
// that word, because P's lowest term is 1, and adds w * 0xc200000000000000
// (y^63 + y^62 + y^57, P's terms from y^121 up, shifted down 64) one word
// higher and w two words higher. Two such steps clear the low 128 bits,
// each with one carry-less multiply, and the high 128 bits are then the
// reduced result, reversed. It is the reduction by the constant 0xc2 that
// Gueron and Kounavis describe for this bit order.
//
// A pass multiplies up to GHASH_PASS_BLOCKS blocks by powers of H before
// it reduces once (SP 800-38D §6.4 regrouped: the last block of a pass
// meets H, the one before it H^2, and the first, with the accumulator
// added, H^8). No block's product waits on another's, so a pass waits on
// one reduction where the one-block form waited on eight. The powers live
// in a ghash_state that the file holding it wipes when its entry ends.
//
// Two instruction sets, and the architecture picks between them, as it
// does for aes_hw.c:
//
//   arm64   PMULL, through vmull_p64 in <arm_neon.h>. The Arm C Language
//           Extensions put the 64-bit PMULL in the AES extension, so the
//           target attribute that gives aes_hw.c its AES instructions
//           gives this header its multiply.
//   x86-64  PCLMULQDQ, through _mm_clmulepi64_si128 in <wmmintrin.h>.
//           x86-64 names it apart from AES-NI, so its attribute is
//           pclmul beside aes.
//
// A host object (-DCH_CPU_RUNTIME, cpu_cfg.h) compiles the files that
// include this header with no instruction flag. The pragma below puts the
// target attribute that turns the instruction on onto each function here,
// as each including file's own pragma does onto its functions; aes_hw.c
// states how each compiler's pragma applies it, and why nothing here
// probes a CPU at run time.
//
// Timing. No line here branches on an operand or indexes memory with
// one: every step is a shift, a mask, an exclusive-or, a move between
// the halves of a register or the instruction. Whether the instruction
// takes the same number of cycles whatever its operands are is a claim
// the instruction's existence does not make, for the reason aes_hw.c
// gives for the AES instructions. The caller's CH_CPU_CONSTANT_TIME_AES
// bit carries that claim for both: its statement that this CPU's AES
// instructions and its carry-less multiply run in constant time. A
// session needs it only for an AES-GCM suite, because under the three
// public keys INV-26 admits, the hash subkey is public too.
//
// CBMC cannot read an intrinsic, so the proofs stay on gcm.c's portable
// multiply, and test/ghash_equiv_test.c holds both files that include
// this header to it byte for byte.
#ifndef CH_GHASH_VECTOR_H
#define CH_GHASH_VECTOR_H
#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#ifdef CH_CPU_RUNTIME

#include <stddef.h>
#include <stdint.h>

#include "aes.h"

// Which instruction the multiply below takes: PMULL where GHASH_VECTOR_ARM
// is defined, and PCLMULQDQ where it is not. The architecture says which,
// because no flag turns the instruction on, and cpu_cfg.h has refused
// every target but these two.
#ifdef __aarch64__
#define GHASH_VECTOR_ARM
#endif

#ifdef GHASH_VECTOR_ARM
#include <arm_neon.h>
#else
#include <wmmintrin.h>
#endif

// Every function from here to the pop at the end of this header carries
// the target attribute that turns the instruction on:
// "+aes", the Arm AES extension, which the Arm C Language Extensions give
// the 64-bit PMULL, or "pclmul", x86-64's PCLMULQDQ.
#ifdef __clang__
#ifdef GHASH_VECTOR_ARM
#pragma clang attribute push(__attribute__((target("+aes"))), apply_to = function)
#else
#pragma clang attribute push(__attribute__((target("pclmul"))), apply_to = function)
#endif
#else
#pragma GCC push_options
#ifdef GHASH_VECTOR_ARM
#pragma GCC target("+aes")
#else
#pragma GCC target("pclmul")
#endif
#endif

// How many blocks a pass multiplies before one reduction, and so how many
// powers of the hash subkey a pass needs. The loop over a pass's blocks
// carries #pragma GCC unroll 8, for the reason aes_hw.c gives, so the
// assertion holds the written-out count to this one.
#define GHASH_PASS_BLOCKS 8
_Static_assert(GHASH_PASS_BLOCKS == 8,
               "each #pragma GCC unroll below writes GHASH_PASS_BLOCKS out");

// The two 64-bit words of 0xc200000000000000: P's terms from y^121 up,
// shifted down 64, which the reduction multiplies by, and the low word
// of x^-1, whose high word is the same constant.
#define GHASH_REDUCTION_WORD 0xc200000000000000U
#define GHASH_INVERSE_X_LOW_WORD 0x1U

// A GF(2^128) element in a vector register holds the 128-bit integer the
// paragraph at the top reverses in two 64-bit lanes: lane 0 holds its
// high word, integer bits 64 to 127, which are bytes 0 to 7 of a block
// read big-endian, and lane 1 its low word, bytes 8 to 15. That is the
// order a byte reversal within each half leaves a block in, one
// instruction on arm64, so loading a block takes no swap. A carry-less
// product of two words sits the other way round, as the instruction
// writes it: lane 0 holds bits 0 to 63. The products and their sums keep
// that order through the reduction, which swaps its result back into an
// element's order.
#ifdef GHASH_VECTOR_ARM
typedef uint64x2_t ghash_vector;

// A block as an element: vld1q_u8 puts byte i in byte lane i, and
// vrev64q_u8 reverses the eight bytes of each half.
static inline ghash_vector ghash_load_block(const uint8_t block[AES_BLOCK]) {
    return vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(block)));
}

static inline void ghash_store_block(uint8_t block[AES_BLOCK], ghash_vector v) {
    vst1q_u8(block, vrev64q_u8(vreinterpretq_u8_u64(v)));
}

static inline ghash_vector ghash_xor(ghash_vector a, ghash_vector b) {
    return veorq_u64(a, b);
}

// (v's lane 1, v's lane 0): the two lanes exchanged.
static inline ghash_vector ghash_swap_halves(ghash_vector v) {
    return vextq_u64(v, v, 1);
}

// (0, v's lane 0): a product shifted up 64 bits.
static inline ghash_vector ghash_low_half_up(ghash_vector v) {
    return vextq_u64(vdupq_n_u64(0), v, 1);
}

// (v's lane 1, 0): a product shifted down 64 bits.
static inline ghash_vector ghash_high_half_down(ghash_vector v) {
    return vextq_u64(v, vdupq_n_u64(0), 1);
}

// (v's lane 0, 0): lane 1 cleared.
static inline ghash_vector ghash_low_half_only(ghash_vector v) {
    return vcombine_u64(vget_low_u64(v), vdup_n_u64(0));
}

// The carry-less product of a's lane 0 and b's lane 0, and of the two
// lanes 1.
static inline ghash_vector ghash_multiply_lane0(ghash_vector a, ghash_vector b) {
    return vreinterpretq_u64_p128(vmull_p64(vgetq_lane_p64(vreinterpretq_p64_u64(a), 0),
                                            vgetq_lane_p64(vreinterpretq_p64_u64(b), 0)));
}

static inline ghash_vector ghash_multiply_lane1(ghash_vector a, ghash_vector b) {
    return vreinterpretq_u64_p128(
        vmull_high_p64(vreinterpretq_p64_u64(a), vreinterpretq_p64_u64(b)));
}

// The vector whose lane 0 holds lane0 and lane 1 lane1.
static inline ghash_vector ghash_vector_of(uint64_t lane0, uint64_t lane1) {
    return vcombine_u64(vcreate_u64(lane0), vcreate_u64(lane1));
}

// v * x^-1 for v in a product's order, the paragraph at the top: v
// shifted left one bit across both lanes, with x^-1 added when bit 127
// moved out. The arithmetic shift of lane 1 by 63 spreads bit 127 into a
// mask of all ones or none.
static inline ghash_vector ghash_times_inverse_x(ghash_vector v) {
    ghash_vector carries = vshrq_n_u64(v, 63);
    ghash_vector shifted = vorrq_u64(vshlq_n_u64(v, 1), ghash_low_half_up(carries));
    ghash_vector top = vdupq_laneq_u64(v, 1);
    ghash_vector mask = vreinterpretq_u64_s64(vshrq_n_s64(vreinterpretq_s64_u64(top), 63));
    ghash_vector inverse_x = ghash_vector_of(GHASH_INVERSE_X_LOW_WORD, GHASH_REDUCTION_WORD);
    return veorq_u64(shifted, vandq_u64(mask, inverse_x));
}
#else
// The same on x86-64, with the same lanes. SSE2 has no byte shuffle, so
// the reversal within each half swaps the bytes of each 16-bit word and
// then the words of each half.
typedef __m128i ghash_vector;

static inline ghash_vector ghash_reverse_halves(ghash_vector v) {
    ghash_vector swapped = _mm_or_si128(_mm_slli_epi16(v, 8), _mm_srli_epi16(v, 8));
    return _mm_shufflehi_epi16(_mm_shufflelo_epi16(swapped, 0x1b), 0x1b);
}

static inline ghash_vector ghash_load_block(const uint8_t block[AES_BLOCK]) {
    return ghash_reverse_halves(_mm_loadu_si128((const __m128i *)(const void *)block));
}

static inline void ghash_store_block(uint8_t block[AES_BLOCK], ghash_vector v) {
    _mm_storeu_si128((__m128i *)(void *)block, ghash_reverse_halves(v));
}

static inline ghash_vector ghash_xor(ghash_vector a, ghash_vector b) {
    return _mm_xor_si128(a, b);
}

static inline ghash_vector ghash_swap_halves(ghash_vector v) {
    return _mm_shuffle_epi32(v, 0x4e);
}

static inline ghash_vector ghash_low_half_up(ghash_vector v) {
    return _mm_slli_si128(v, 8);
}

static inline ghash_vector ghash_high_half_down(ghash_vector v) {
    return _mm_srli_si128(v, 8);
}

static inline ghash_vector ghash_low_half_only(ghash_vector v) {
    return _mm_move_epi64(v);
}

// Bit 0 of the immediate picks a's lane and bit 4 picks b's.
static inline ghash_vector ghash_multiply_lane0(ghash_vector a, ghash_vector b) {
    return _mm_clmulepi64_si128(a, b, 0x00);
}

static inline ghash_vector ghash_multiply_lane1(ghash_vector a, ghash_vector b) {
    return _mm_clmulepi64_si128(a, b, 0x11);
}

static inline ghash_vector ghash_vector_of(uint64_t lane0, uint64_t lane1) {
    return _mm_set_epi64x((long long)lane1, (long long)lane0);
}

// The arithmetic shift of the top 32-bit lane, copied into all four,
// spreads bit 127 into the mask.
static inline ghash_vector ghash_times_inverse_x(ghash_vector v) {
    ghash_vector carries = _mm_srli_epi64(v, 63);
    ghash_vector shifted = _mm_or_si128(_mm_slli_epi64(v, 1), ghash_low_half_up(carries));
    ghash_vector mask = _mm_srai_epi32(_mm_shuffle_epi32(v, 0xff), 31);
    ghash_vector inverse_x = ghash_vector_of(GHASH_INVERSE_X_LOW_WORD, GHASH_REDUCTION_WORD);
    return _mm_xor_si128(shifted, _mm_and_si128(mask, inverse_x));
}
#endif

// The three products of one or more pairs of elements, added up before
// the middle term is formed: low sums the products of the two low words,
// high those of the two high words, and middle those of each element's
// two words added together.
typedef struct {
    ghash_vector low;
    ghash_vector high;
    ghash_vector middle;
} ghash_sums;

// A power of the hash subkey times x^-1, and its two words added in both
// lanes: the middle product's operand, computed once for every block that
// takes the power.
typedef struct {
    ghash_vector power;
    ghash_vector halves_added;
} ghash_power;

// Everything the multiplies compute from the hash subkey, in one object
// so that one wipe at the end of an entry clears all of it. powers comes
// last, so an entry that computed only some of them can wipe up to the
// last one it wrote.
typedef struct {
    ghash_vector subkey; // the hash subkey H
    ghash_vector acc;    // the accumulator
    ghash_sums sums;     // the products a multiply or a pass adds up, before ghash_reduce
    ghash_power powers[GHASH_PASS_BLOCKS]; // powers[i] holds H^(i + 1) * x^-1
} ghash_state;

// v's two words added, in both lanes.
static inline ghash_vector ghash_halves_added(ghash_vector v) {
    return ghash_xor(v, ghash_swap_halves(v));
}

// A power and its halves added, read from s through a volatile lvalue,
// so the compiler reads the state each time a multiply takes them rather
// than holding the eight powers in registers across a pass. Held there,
// they did not fit beside a pass's blocks: clang and gcc both copied some
// of them, or their halves added, to stack slots of their own, which the
// wipe of s does not clear, and test/ghash_equiv_residue.h found the
// copies.
static inline ghash_vector ghash_power_at(const ghash_state *s, size_t i) {
    const volatile ghash_vector *power = &s->powers[i].power;
    return *power;
}

static inline ghash_vector ghash_halves_at(const ghash_state *s, size_t i) {
    const volatile ghash_vector *halves = &s->powers[i].halves_added;
    return *halves;
}

// sums = the three products of the element x and powers[i], or sums +=
// them. The low words sit in lane 1 and the high words in lane 0, and the
// words added sit in both lanes.
static inline void ghash_start_sums(const ghash_state *s, ghash_sums *sums, ghash_vector x,
                                    size_t i) {
    ghash_vector power = ghash_power_at(s, i);
    sums->low = ghash_multiply_lane1(x, power);
    sums->high = ghash_multiply_lane0(x, power);
    sums->middle = ghash_multiply_lane0(ghash_halves_added(x), ghash_halves_at(s, i));
}

static inline void ghash_add_products(const ghash_state *s, ghash_sums *sums, ghash_vector x,
                                      size_t i) {
    ghash_sums products;
    ghash_start_sums(s, &products, x, i);
    sums->low = ghash_xor(sums->low, products.low);
    sums->high = ghash_xor(sums->high, products.high);
    sums->middle = ghash_xor(sums->middle, products.middle);
}

// The sum of products modulo the field polynomial, the paragraphs at the
// top, as an element. The product's four 64-bit words, w0 the lowest,
// come from the three sums, with the middle term between the other two:
//
//   w0 = low's lane 0            w2 = high's lane 0 + middle's lane 1
//   w1 = low's lane 1 + middle's lane 0          w3 = high's lane 1
//
// The first step clears w0. first holds the new w1 in lane 0 and, in
// lane 1, what the step adds to w2: w0 itself, plus the high half of w0
// times 0xc200000000000000, whose low half lane 0 takes. w0 is low's lane
// 0 alone, so that multiply need not wait for the middle term. The second
// step clears the new w1 the same way, and what is left is w2 and w3, in
// a product's order, which the last swap turns into an element's.
static inline ghash_vector ghash_reduce(const ghash_sums *sums) {
    ghash_vector constant = ghash_vector_of(GHASH_REDUCTION_WORD, 0);
    ghash_vector middle = ghash_xor(sums->middle, ghash_xor(sums->low, sums->high));
    ghash_vector first =
        ghash_xor(ghash_xor(ghash_swap_halves(sums->low), ghash_low_half_only(middle)),
                  ghash_multiply_lane0(sums->low, constant));
    ghash_vector upper = ghash_xor(sums->high, ghash_high_half_down(middle));
    ghash_vector second =
        ghash_xor(ghash_swap_halves(first), ghash_multiply_lane0(first, constant));
    return ghash_swap_halves(ghash_xor(upper, second));
}

// s->powers[i] = power and its two words added.
static inline void ghash_set_power(ghash_state *s, size_t i, ghash_vector power) {
    s->powers[i].power = power;
    s->powers[i].halves_added = ghash_halves_added(power);
}

// s->powers[i] holds H^(i + 1) * x^-1 for each i below count, which is at
// least 1 and at most GHASH_PASS_BLOCKS, from s->subkey. The shift runs in
// a product's order, between two swaps. H^(i + 1) is H^half times
// H^(i + 1 - half), half the largest power of two at or below i, so the
// seven multiplies run in three rounds, H^2, then H^3 and H^4, then H^5 to
// H^8, and no multiply waits on another of its round.
static inline void ghash_compute_powers(ghash_state *s, size_t count) {
    ghash_set_power(s, 0, ghash_swap_halves(ghash_times_inverse_x(ghash_swap_halves(s->subkey))));
    for (size_t i = 1; i < count; i++) {
        size_t half = 1;
        while (2 * half <= i) {
            half *= 2;
        }
        ghash_start_sums(s, &s->sums, ghash_power_at(s, half - 1), i - half);
        ghash_set_power(s, i, ghash_reduce(&s->sums));
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
// the other blocks can run while it finishes. s->powers must hold the
// first count powers.
static inline void ghash_hash_blocks(ghash_state *s, const uint8_t *data, size_t count) {
    ghash_vector first = ghash_xor(ghash_load_block(data), s->acc);
    if (count == 1) {
        ghash_start_sums(s, &s->sums, first, 0);
    } else {
        ghash_start_sums(s, &s->sums, ghash_load_block(&data[AES_BLOCK]), count - 2);
        for (size_t j = 2; j < count; j++) {
            ghash_add_products(s, &s->sums, ghash_load_block(&data[j * AES_BLOCK]), count - 1 - j);
        }
        ghash_add_products(s, &s->sums, first, count - 1);
    }
    s->acc = ghash_reduce(&s->sums);
}

// ghash_hash_blocks over GHASH_PASS_BLOCKS blocks, with the count written
// out so the compiler unrolls the loop.
static inline void ghash_hash_pass(ghash_state *s, const uint8_t *data) {
    ghash_start_sums(s, &s->sums, ghash_load_block(&data[AES_BLOCK]), GHASH_PASS_BLOCKS - 2);
#pragma GCC unroll 8
    for (size_t j = 2; j < GHASH_PASS_BLOCKS; j++) {
        ghash_add_products(s, &s->sums, ghash_load_block(&data[j * AES_BLOCK]),
                           GHASH_PASS_BLOCKS - 1 - j);
    }
    ghash_add_products(s, &s->sums, ghash_xor(ghash_load_block(data), s->acc),
                       GHASH_PASS_BLOCKS - 1);
    s->acc = ghash_reduce(&s->sums);
}

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif

#endif // CH_CPU_RUNTIME
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
#endif
