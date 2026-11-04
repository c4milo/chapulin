#include "poly1305_ifma.h"

// The whole file compiles only under CH_POLY1305_IFMA (poly1305_ifma.h):
// in an x86-64 host object's native copy.
#ifdef CH_POLY1305_IFMA

// avx512_wipe.h comes before the attribute push below, so its declaration
// carries no target attribute: clang reads a declaration under the push
// and avx512_wipe.c's definition under target("avx512f") alone as two
// versions of one function, and refuses a unit that holds both.
#include "avx512_wipe.h"
#include "ch_assert.h"
#include "ct.h"
// carry_scalar alone: the kernel computes its powers of r in the lanes.
#define POLY1305_SCALAR_CARRY_ONLY
#include "poly1305_scalar.h"

#ifdef CH_POLY1305_IFMA_MODEL
// Each lane operation in portable C (test/poly1305_ifma_model_lanes.h),
// which only a build with -Itest finds.
#include "poly1305_ifma_model_lanes.h"
#else
// Every function from here to the pop at the end of this file carries the
// target attribute that turns AVX-512F and AVX-512 IFMA on, and no function
// outside it does, as in poly1305_avx2.c: poly1305_scalar.h's carry above
// compiles without it. The object is compiled with no instruction flag,
// and build.zig adds only the evex512 feature, which turns on no
// instruction. So only these functions hold AVX-512 instructions, and
// poly1305.c calls them only for an update that
// widemul_poly1305_update_cpu started for a session whose ch_cfg.cpu holds
// CH_CPU_AVX512_IFMA beside the multiply bit.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx512f,avx512ifma"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx512f,avx512ifma")
#endif

#include "poly1305_ifma_lanes.h"
#endif

typedef poly1305_ifma_lanes lanes;

// A number here is three digits, x = x0 + x1 2^44 + x2 2^88: x0 and x1 hold
// 44 bits when carried and x2 42, which is 130 bits. Modulo
// p = 2^130 - 5, 2^132 is 4 * 5 = 20, so a product's parts at 2^132 and
// 2^176 come back at 2^0 and 2^44 times 20, and a part at 2^130 comes back
// times 5.
#define DIGIT_MASK ((UINT64_C(1) << 44) - 1)
#define TOP_MASK ((UINT64_C(1) << 42) - 1)
// The 2^128 bit of a whole block, bit 40 of its top digit.
#define HIGH_BIT (UINT64_C(1) << 40)

// 20 times each lane, as 16 times it plus 4 times it.
static inline lanes lanes_times_20(lanes a) {
    return lanes_add(lanes_shift_left(a, 4), lanes_shift_left(a, 2));
}

// 5 times each lane, as the lane plus 4 times it.
static inline lanes lanes_times_5(lanes a) {
    return lanes_add(a, lanes_shift_left(a, 2));
}

// The three digits of the eight blocks at m, each with its 2^128 bit. The
// first 64 bytes hold blocks 0 to 3, a block's two halves in two lanes
// side by side, and the next 64 blocks 4 to 7. VPUNPCKLQDQ and VPUNPCKHQDQ
// pair the lanes of the two loads, so lanes 0 to 7 take blocks 0, 4, 1, 5,
// 2, 6, 3 and 7, block b_l in lane l. A lane holds eight bytes of a block,
// little-endian, as RFC 8439 §2.5.1 reads them.
static inline void load_blocks(lanes out[3], const uint8_t *m) {
    lanes first = lanes_load_bytes(m);
    lanes second = lanes_load_bytes(m + 64);
    lanes low = lanes_interleave_low(first, second);
    lanes high = lanes_interleave_high(first, second);
    lanes mask = lanes_broadcast(DIGIT_MASK);
    out[0] = lanes_and(low, mask);
    out[1] = lanes_and(lanes_or(lanes_shift_right(low, 44), lanes_shift_left(high, 20)), mask);
    out[2] = lanes_or(lanes_shift_right(high, 24), lanes_broadcast(HIGH_BIT));
}

// A power of r in each lane: its three digits, and 20 times the two whose
// products pass 2^132.
typedef struct {
    lanes r0, r1, r2;
    lanes s1, s2;
} multiplier;

// multiply_add reads each vector of a multiplier through a volatile
// pointer, as poly1305_avx2.c does, so that a product loads the vector
// from the struct where it uses it, and the powers stay in the one struct
// the call wipes rather than in a stack slot the compiler picks, which
// ct_wipe cannot name. A group's two multipliers are ten vectors, and
// AVX-512 has 32 registers, but the compiler is free to keep any of them
// on the stack across the loop.
typedef const volatile multiplier multiplier_read;

// by's two multiples by 20, from its digits, written into the struct.
static void multiplier_complete(multiplier *by) {
    by->s1 = lanes_times_20(by->r1);
    by->s2 = lanes_times_20(by->r2);
}

// The six sums of a product of a by by: lo[i] adds bits 0 to 51 and hi[i]
// bits 52 to 103 of each partial product at 2^(44 i), for
//
//   d0 = a0 r0 + a1 (20 r2) + a2 (20 r1)
//   d1 = a0 r1 + a1 r0      + a2 (20 r2)
//   d2 = a0 r2 + a1 r1      + a2 r0
//
// a1 and a2 come first: a0 is the digit the carry below finishes last. It
// and group_sums carry always_inline for poly1305_avx2.c's reason: gcc
// otherwise compiled them out of line and passed the sums through the
// stack (docs/decisions.md 110).
static inline __attribute__((always_inline)) void
multiply_add(lanes lo[3], lanes hi[3], const lanes a[3], multiplier_read *by) {
    lo[0] = lanes_multiply_add_low(lo[0], a[1], by->s2);
    hi[0] = lanes_multiply_add_high(hi[0], a[1], by->s2);
    lo[1] = lanes_multiply_add_low(lo[1], a[1], by->r0);
    hi[1] = lanes_multiply_add_high(hi[1], a[1], by->r0);
    lo[2] = lanes_multiply_add_low(lo[2], a[1], by->r1);
    hi[2] = lanes_multiply_add_high(hi[2], a[1], by->r1);
    lo[0] = lanes_multiply_add_low(lo[0], a[2], by->s1);
    hi[0] = lanes_multiply_add_high(hi[0], a[2], by->s1);
    lo[1] = lanes_multiply_add_low(lo[1], a[2], by->s2);
    hi[1] = lanes_multiply_add_high(hi[1], a[2], by->s2);
    lo[2] = lanes_multiply_add_low(lo[2], a[2], by->r0);
    hi[2] = lanes_multiply_add_high(hi[2], a[2], by->r0);
    lo[0] = lanes_multiply_add_low(lo[0], a[0], by->r0);
    hi[0] = lanes_multiply_add_high(hi[0], a[0], by->r0);
    lo[1] = lanes_multiply_add_low(lo[1], a[0], by->r1);
    hi[1] = lanes_multiply_add_high(hi[1], a[0], by->r1);
    lo[2] = lanes_multiply_add_low(lo[2], a[0], by->r2);
    hi[2] = lanes_multiply_add_high(hi[2], a[0], by->r2);
}

// The six sums of each lane carried into three digits in one round. A
// lane's value is lo0 + 2^52 hi0 + 2^44 (lo1 + 2^52 hi1) + 2^88 (lo2 +
// 2^52 hi2), where 2^52 = 2^44 2^8, 2^96 = 2^88 2^8 and 2^140 is 5 2^10
// modulo p. So t0 = lo0 + 5 (hi2 << 10), t1 = lo1 + (hi0 << 8) and t2 =
// lo2 + (hi1 << 8) hold the value at 2^0, 2^44 and 2^88, and the round
// keeps each one's low bits and adds the bits above them to the digit above,
// t2's above bit 42, at 2^130, times 5 to digit 0. With every lo sum below
// 2^55 and every hi sum below 2^42, which the carried digits and the blocks
// give, t0, t1 and t2 are below 2^56, and the round leaves h0 below
// 2^44 + 5 * 2^14, h1 below 2^44 + 2^12 and h2 below 2^42 + 2^12.
static inline __attribute__((always_inline)) void carry(lanes h[3], const lanes lo[3],
                                                        const lanes hi[3]) {
    lanes mask = lanes_broadcast(DIGIT_MASK);
    lanes t0 = lanes_add(lo[0], lanes_times_5(lanes_shift_left(hi[2], 10)));
    lanes t1 = lanes_add(lo[1], lanes_shift_left(hi[0], 8));
    lanes t2 = lanes_add(lo[2], lanes_shift_left(hi[1], 8));
    h[0] = lanes_add(lanes_and(t0, mask), lanes_times_5(lanes_shift_right(t2, 42)));
    h[1] = lanes_add(lanes_and(t1, mask), lanes_shift_right(t0, 44));
    h[2] = lanes_add(lanes_and(t2, lanes_broadcast(TOP_MASK)), lanes_shift_right(t1, 44));
}

// Every array of vectors here is indexed by constants alone, and written
// out rather than looped over, so that no compiler keeps a lane's sum in a
// stack slot to walk it with an index.
static inline __attribute__((always_inline)) void sums_zero(lanes lo[3], lanes hi[3]) {
    lo[0] = lanes_zero();
    lo[1] = lanes_zero();
    lo[2] = lanes_zero();
    hi[0] = lanes_zero();
    hi[1] = lanes_zero();
    hi[2] = lanes_zero();
}

// The sums for the group of sixteen blocks at m. Lane l takes block b_l of
// the group's first eight and block 8 + b_l of its last eight, b_l as
// load_blocks gives it, so each lane runs Horner's rule over every eighth
// block:
//
//   d = (h + the lane's first block) * first + (the lane's second block) * second
static inline __attribute__((always_inline)) void group_sums(lanes lo[3], lanes hi[3],
                                                             const lanes h[3], const uint8_t *m,
                                                             multiplier_read *first,
                                                             multiplier_read *second) {
    lanes first_blocks[3];
    lanes second_blocks[3];
    load_blocks(first_blocks, m);
    load_blocks(second_blocks, m + 128);
    first_blocks[0] = lanes_add(first_blocks[0], h[0]);
    first_blocks[1] = lanes_add(first_blocks[1], h[1]);
    first_blocks[2] = lanes_add(first_blocks[2], h[2]);
    sums_zero(lo, hi);
    // The second blocks' products first: they do not wait on h.
    multiply_add(lo, hi, second_blocks, second);
    multiply_add(lo, hi, first_blocks, first);
}

// Five 26-bit words, each at most 2^26, as three digits: the same number,
// unreduced, with the low two digits below 2^44 and the top one below
// 2^42 + 2^17.
static void digits_of_words(uint64_t out[3], const uint32_t w[5]) {
    uint64_t l0 = (uint64_t)w[0] + ((uint64_t)w[1] << 26);
    uint64_t l1 = ((uint64_t)w[2] << 8) + ((uint64_t)w[3] << 34);
    uint64_t l2 = (uint64_t)w[4] << 16;
    l1 += l0 >> 44;
    l0 &= DIGIT_MASK;
    l2 += l1 >> 44;
    l1 &= DIGIT_MASK;
    out[0] = l0;
    out[1] = l1;
    out[2] = l2;
}

// What one call derives from r, in one struct the call wipes when it ends:
// r's digits, two multipliers the powers pass through on the way, and the
// four the groups take. Every group but the last multiplies each lane by
// by_16 and by_8, r^16 and r^8 in every lane. The last multiplies lane l
// by last_first, r^(16 - b_l), and last_second, r^(8 - b_l), the powers
// its two blocks are owed, b_l as load_blocks gives it. Every vector a
// power passes through is a member here, read and written in place.
typedef struct {
    uint64_t r[3];
    multiplier r1_r2[2]; // r and r^2 in every lane
    multiplier last_first;
    multiplier last_second;
    multiplier by_16;
    multiplier by_8;
} powers;

// out = a * b in each lane, carried by one round. a and b may be the same
// struct, and out may be either.
static void multiplier_product(multiplier *out, multiplier_read *a, multiplier_read *b) {
    const lanes a_digits[3] = {a->r0, a->r1, a->r2};
    lanes lo[3];
    lanes hi[3];
    lanes h[3];
    sums_zero(lo, hi);
    multiply_add(lo, hi, a_digits, b);
    carry(h, lo, hi);
    out->r0 = h[0];
    out->r1 = h[1];
    out->r2 = h[2];
    multiplier_complete(out);
}

// Lane l of out takes lane l of b where bit l of bits is set and of a
// where it is clear: VPBLENDMQ under a constant mask, so which lane moves
// where depends on the mask alone.
static void multiplier_select(multiplier *out, poly1305_ifma_lane_bits bits, multiplier_read *a,
                              multiplier_read *b) {
    out->r0 = lanes_select(bits, a->r0, b->r0);
    out->r1 = lanes_select(bits, a->r1, b->r1);
    out->r2 = lanes_select(bits, a->r2, b->r2);
    multiplier_complete(out);
}

// Lane l of out takes lane l of b where bit l of bits is set, and 1 where
// it is clear.
static void multiplier_select_one(multiplier *out, poly1305_ifma_lane_bits bits,
                                  multiplier_read *b) {
    out->r0 = lanes_select(bits, lanes_broadcast(1), b->r0);
    out->r1 = lanes_keep(bits, b->r1);
    out->r2 = lanes_keep(bits, b->r2);
    multiplier_complete(out);
}

// Lane 0 of by in every lane of out.
static void multiplier_first(multiplier *out, multiplier_read *by) {
    out->r0 = lanes_broadcast_first(by->r0);
    out->r1 = lanes_broadcast_first(by->r1);
    out->r2 = lanes_broadcast_first(by->r2);
    multiplier_complete(out);
}

// The four multipliers from r, in five products in the lanes. Writing
// r^[e0, ..., e7] for lane l holding r^el, the last group's second
// multiplier is r^[8, 4, 7, 3, 6, 2, 5, 1], which is
// r^[2, 2, 2, 2, 1, 1, 1, 1] * r^[2, 2, 1, 1, 1, 1, 0, 0] *
// r^[4, 0, 4, 0, 4, 0, 4, 0]. Its lane 0, r^8, times it is the last group's
// first multiplier, r^[16, 12, 15, 11, 14, 10, 13, 9], whose lane 0 is r^16.
static void compute_powers(powers *of_r, const uint32_t r[5]) {
    multiplier *r_one = &of_r->r1_r2[0];
    multiplier *r_two = &of_r->r1_r2[1];
    digits_of_words(of_r->r, r);
    r_one->r0 = lanes_broadcast(of_r->r[0]);
    r_one->r1 = lanes_broadcast(of_r->r[1]);
    r_one->r2 = lanes_broadcast(of_r->r[2]);
    multiplier_complete(r_one);
    multiplier_product(r_two, r_one, r_one);                    // r^2
    multiplier_product(&of_r->by_8, r_two, r_two);              // r^4
    multiplier_select(&of_r->last_second, 0x0f, r_one, r_two);  // r^[2,2,2,2,1,1,1,1]
    multiplier_select_one(&of_r->by_16, 0x3f, r_one);           // r^[1,1,1,1,1,1,0,0]
    multiplier_select(&of_r->by_16, 0x03, &of_r->by_16, r_two); // r^[2,2,1,1,1,1,0,0]
    multiplier_product(&of_r->last_first, &of_r->last_second, &of_r->by_16);
    multiplier_select_one(&of_r->by_8, 0x55, &of_r->by_8); // r^[4,0,4,0,4,0,4,0]
    multiplier_product(&of_r->last_second, &of_r->last_first, &of_r->by_8);
    multiplier_first(&of_r->by_8, &of_r->last_second); // r^8
    multiplier_product(&of_r->last_first, &of_r->last_second, &of_r->by_8);
    multiplier_first(&of_r->by_16, &of_r->last_first); // r^16
}

// Three digit totals, each below 2^48, as five sums of 26-bit words for
// carry_scalar: T0 + T1 2^44 + T2 2^88, where 2^44 is 2^26 2^18, 2^52 is
// word 2's place, 2^88 is 2^78 2^10 and 2^104 is word 4's place.
static void words_of_totals(uint32_t h[5], const uint64_t total[3]) {
    uint64_t d[5];
    d[0] = total[0] & WORD_MASK;
    d[1] = (total[0] >> 26) + ((total[1] & 0xff) << 18);
    d[2] = total[1] >> 8;
    d[3] = (total[2] & 0xffff) << 10;
    d[4] = total[2] >> 16;
    carry_scalar(h, d);
}

void poly1305_ifma_blocks(poly1305 *p, const uint8_t *m, size_t n) {
    CH_ASSERT(n > 0 && n % POLY1305_IFMA_GROUP == 0);
    powers of_r;
    compute_powers(&of_r, p->r);

    // Lane 0 starts from the accumulator and lanes 1 to 7 from 0.
    uint64_t start[3];
    digits_of_words(start, p->h);
    lanes h[3];
    h[0] = lanes_first_only(start[0]);
    h[1] = lanes_first_only(start[1]);
    h[2] = lanes_first_only(start[2]);
    lanes lo[3];
    lanes hi[3];
    for (; n > POLY1305_IFMA_GROUP; n -= POLY1305_IFMA_GROUP) {
        group_sums(lo, hi, h, m, &of_r.by_16, &of_r.by_8);
        carry(h, lo, hi);
        m += POLY1305_IFMA_GROUP;
    }
    group_sums(lo, hi, h, m, &of_r.last_first, &of_r.last_second);
    carry(h, lo, hi);

    // The eight lanes' digits add up to the accumulator. Each digit is below
    // 2^45, so each total is below 2^48.
    uint64_t total[3];
    total[0] = lanes_total(h[0]);
    total[1] = lanes_total(h[1]);
    total[2] = lanes_total(h[2]);
    // The powers, the sums and the accumulator's lanes passed through the
    // vector registers, and the compiler clears none of them on return:
    // lanes_wipe_registers is avx512_wipe_registers. No vector is live past
    // this call, so the compiler keeps none on the stack across it.
    lanes_wipe_registers();
    words_of_totals(p->h, total);
    ct_wipe(&of_r, sizeof of_r);
}

#ifndef CH_POLY1305_IFMA_MODEL
#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif
#endif

#endif // CH_POLY1305_IFMA
