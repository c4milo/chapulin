// RSA's public operation on AVX2 (rsa_avx2.h): base^65537 mod m, on
// numbers in digits of D bits, one digit to a 64-bit lane and four lanes
// to a 256-bit register.
//
// A number has digit j at lane PAD + j (rsa_avx2_number.h). The product's
// running sum is lanes, lane p for digit position p, in registers of four
// lanes, none of which carries into the next until the end.
//
// The product is the almost-Montgomery multiplication in radix 2^D with
// R' = 2^(Dn), by operand scanning with the reduction interleaved. Row i
// adds b_i * a and y_i * m at digit i, where y_i is the digit below 2^D
// that makes the sum's lane i a multiple of 2^D. The sum never moves down
// a digit: lanes 0 to n - 1 end as zeros, and lanes n to 2n - 1, after one
// pass of carries, hold (a * b + Y * m) / R', for Y = sum y_i 2^(Di),
// which is below R'.
//
// Rows go four at a time, a group to each register of the sum. Row 4g + t
// adds b_(4g+t) times a moved up 4g + t digits, so register g + j of the
// sum takes a's digits 4j - t to 4j - t + 3: four lanes of a loaded from
// lane PAD + 4j - t, view t of a's register j, which need not be aligned.
// The PAD zeros below digit 0 are what the views of register 0 read below
// it. The rows of m go the same way.
//
// The triangle. The y's of group g depend on its own register: y_(4g+t)
// comes from lane t once rows 4g to 4g + t - 1 have added their y's times
// m's low digits there. So a scalar step reads the register's four lanes,
// computes the four y's in turn, adds y_t times m's digits 1 to 3 - t to
// the lanes above lane t, and carries each lane's bits above D into the
// lane above. The register's lanes are then zero, and the carry out of
// lane 3 goes to the next register's lane 0, which the next triangle adds.
// The vector side adds the group's y's times m and its rows of a to every
// register above. The register the next group's triangle reads is updated
// first, so that the triangle need not wait on the rest of the group.
//
// The window. Group g adds to registers g + 1 to g + G alone, for G
// groups, and once its triangle has run, register g is zero and no row
// adds to it again. So the sum is kept in G + 1 registers, the window,
// which holds registers g to g + G when group g starts. Each group writes
// each register it adds to one register lower than it read it. No group
// but the last writes the top one, which the start zeroed, and register
// g + G is zero when group g reads it there, for no group before g adds
// to it; so the window holds registers g + 1 to g + G + 1 when the next
// group starts. The last group writes in place, and leaves registers
// G - 1 to 2G - 1, which hold the result's lanes.
//
// The square adds a_r * a_s once for r < s, as 2 a_r times a_s, and a_r^2
// once: row r multiplies a's digits from r up, a_r by a_r and those above
// it by 2 a_r, and nothing below. Lane l of register g + j takes row
// 4g + t's product with a's digit s = 4j + l - t, so group g's rows add
// nothing at offsets j below g, 2 a_r in every lane at offsets g + 2 and
// up, and at offsets g and g + 1 a fixed pattern of a_r, 2 a_r and zero,
// which a blend of the two multipliers makes. So each lane of a square's
// sum holds what the multiplication of a by itself puts there, from about
// half its products of digits of a.
//
// The bound. A lane of the sum receives at most 2n products below
// 2^(2D), counting the square's 2 a_r a_s as two, and at most two carries
// below 2^(64 - D): one from a triangle and one from the last pass. For
// D = 28 and n = 110 that is below 220 * 2^56 + 2^37 < 2^64, and for
// D = 27 and n = 152 below 304 * 2^54 + 2^38 < 2^64, so no lane wraps. A
// product of a and b is below a * b / R' + m: below 2m when a is below R'
// and b below m, and when a and b are both below 2m and 4m <= R', which
// the two spare bits of RSA_AVX2_DIGIT_COUNT give.
//
// Every branch and every memory index here depends on the word count, the
// digit count, the group count, a row's index or a register's index. The
// inputs are public all the same, and nothing is wiped: the compiler keeps
// 256-bit registers in stack slots that no wipe can name, which is why
// only verification calls this file (rsa_avx2.h).
#include "rsa_avx2.h"

// The whole file compiles only in a host object on x86-64, or in a test
// unit that defines CH_RSA_AVX2_MODEL (rsa_avx2.h).
#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_RSA_AVX2_MODEL))

#include <string.h>

#include "ch_assert.h"

#ifdef CH_RSA_AVX2_MODEL
// Each lane operation in portable C (test/rsa_avx2_model_lanes.h), which
// only a build with -Itest finds.
#include "rsa_avx2_model_lanes.h"
#else
// Every function from here to the pop at the end of this file carries the
// target attribute that turns AVX2 on, as in chacha20_avx2.c, and make and
// build.zig compile the object with no instruction flag, so only these
// functions hold AVX2 instructions. rsa_mont.c calls rsa_avx2_public only
// where the caller's CH_CPU_AVX2 bit says the CPU has them.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx2"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx2")
#endif

#include "rsa_avx2_lanes.h"
#endif

// PAD, NUMBER_LANES, the modulus's record and the conversions between a
// number and words.
#include "rsa_avx2_number.h"

// The window's lanes: GROUPS_MAX + 1 registers of the sum.
#define WINDOW_LANES (4 * (GROUPS_MAX + 1))

// The four multipliers of a group's rows, digits[0..3] in every lane of
// x[0..3]. Every digit is below 2^bits, so the AND with mask changes no
// value. It is there for clang, which multiplies on one VPMULUDQ only
// where it can show that a multiplier's bits from 32 up are zero, and in
// a loop it showed that only of a value an AND wrote in the same pass.
// Without the AND it multiplied by b's digits, and by a y it had carried
// over from the last group in a register, on two VPMULUDQs, two shifts
// and an add. digits is read through a volatile pointer, so that each
// group reads the y's from memory, and the compiler cannot drop the AND
// because the triangle that wrote them masked them already. The four
// statements are written out: gcc kept the array a loop fills in memory,
// and reloaded it in every row. test/widemul-builds.sh refuses an object
// of this file that shifts a lane left by 32.
static inline __attribute__((always_inline)) void
broadcast_four(rsa_avx2_lanes x[4], const volatile uint64_t *digits, uint64_t mask) {
    x[0] = lanes_broadcast(digits[0] & mask);
    x[1] = lanes_broadcast(digits[1] & mask);
    x[2] = lanes_broadcast(digits[2] & mask);
    x[3] = lanes_broadcast(digits[3] & mask);
}

// The four multipliers of a square's rows above their own digits, twice
// digits[0..3] in every lane of twice[0..3], from the masked digits as in
// broadcast_four. The kernel doubles a multiplier rather than a: with 2a
// as a number in memory, which the views read across two of the stores
// that had just written it, some gcc processes ran the whole kernel 1.5
// times slower (docs/decisions.md 122).
static inline __attribute__((always_inline)) void
broadcast_twice_four(rsa_avx2_lanes twice[4], const uint64_t *digits, uint64_t mask) {
    twice[0] = lanes_broadcast((digits[0] & mask) << 1);
    twice[1] = lanes_broadcast((digits[1] & mask) << 1);
    twice[2] = lanes_broadcast((digits[2] & mask) << 1);
    twice[3] = lanes_broadcast((digits[3] & mask) << 1);
}

// acc plus the products of x[t], the multiplier of row t of a group, by
// view t of number's register j, for t = 0 to 3.
static inline __attribute__((always_inline)) rsa_avx2_lanes add_rows(rsa_avx2_lanes acc,
                                                                     const uint64_t *number,
                                                                     const rsa_avx2_lanes x[4],
                                                                     size_t j) {
    const uint64_t *lanes = number + PAD + 4 * j;
    rsa_avx2_lanes p0 = lanes_multiply(x[0], lanes_load(lanes));
    rsa_avx2_lanes p1 = lanes_multiply(x[1], lanes_load(lanes - 1));
    rsa_avx2_lanes p2 = lanes_multiply(x[2], lanes_load(lanes - 2));
    rsa_avx2_lanes p3 = lanes_multiply(x[3], lanes_load(lanes - 3));
    return lanes_add(acc, lanes_add(lanes_add(p0, p1), lanes_add(p2, p3)));
}

// acc plus a square's products of group g's rows at register offset j:
// digit[t] holds a_(4g+t) in every lane and twice[t] twice it. Row t
// multiplies a's digit 4j + l - t in lane l, which is its own digit, a
// digit above it or a digit below it by the offset alone.
static inline __attribute__((always_inline)) rsa_avx2_lanes
add_square_rows(rsa_avx2_lanes acc, const uint64_t *a, const rsa_avx2_lanes digit[4],
                const rsa_avx2_lanes twice[4], size_t g, size_t j) {
    if (j >= g + 2) {
        return add_rows(acc, a, twice, j);
    }
    if (j == g + 1) {
        // Rows 0 and 1 meet digits above their own in every lane. Row 2's
        // own digit is lane 0, and row 3's is lane 2, with lanes 0 and 1
        // below it.
        rsa_avx2_lanes x[4] = {twice[0], twice[1], lanes_first_from(twice[2], digit[2]),
                               lanes_upper_two(twice[3], digit[3])};
        return add_rows(acc, a, x, j);
    }
    if (j == g) {
        // Row 0's own digit is lane 0. Row 1's is lane 2, with lanes 0 and
        // 1 below it. Rows 2 and 3 meet digits below their own alone.
        rsa_avx2_lanes x[4] = {lanes_first_from(twice[0], digit[0]),
                               lanes_upper_two(twice[1], digit[1]), lanes_zero(), lanes_zero()};
        return add_rows(acc, a, x, j);
    }
    return acc;
}

// The triangle of group g on the four lanes of the sum's register g, in
// turn. Row t's y makes lane t a multiple of 2^bits, adds y times m's
// digits 1 to 3 - t to the lanes above, and the lane's bits above bits
// move to the lane above as a carry. It writes the four y's to y and the
// lanes back, zeros in a row below n. *carry holds what moved out of the
// last register's lane 3 on entry, and what moves out of this one's on
// return. A row at or past n, which only the last group has, has a y of 0,
// and its lane carries alone, so the lanes of rows n and up hold digits of
// the result. bits is a constant in each copy of the product, so the
// shifts and masks take immediates.
static inline __attribute__((always_inline)) void triangle(uint64_t *lanes, uint64_t *carry,
                                                           uint64_t y[4],
                                                           const rsa_avx2_modulus *mod, size_t g,
                                                           unsigned bits) {
    const uint64_t *m = mod->digits + PAD;
    const uint64_t mask = ((uint64_t)1 << bits) - 1;
    const uint64_t k0 = mod->k0;
    size_t rows = mod->digit_count - 4 * g; // at least 1: g is below the group count
    uint64_t step1 = rows > 1 ? mask : 0;
    uint64_t step2 = rows > 2 ? mask : 0;
    uint64_t step3 = rows > 3 ? mask : 0;
    uint64_t l0 = lanes[0] + *carry;
    uint64_t l1 = lanes[1];
    uint64_t l2 = lanes[2];
    uint64_t l3 = lanes[3];
    uint64_t y0 = ((l0 & mask) * k0) & mask;
    uint64_t x = l0 + y0 * m[0];
    l1 += y0 * m[1] + (x >> bits);
    l2 += y0 * m[2];
    l3 += y0 * m[3];
    lanes[0] = x & mask;
    uint64_t y1 = ((l1 & mask) * k0) & step1;
    x = l1 + y1 * m[0];
    l2 += y1 * m[1] + (x >> bits);
    l3 += y1 * m[2];
    lanes[1] = x & mask;
    uint64_t y2 = ((l2 & mask) * k0) & step2;
    x = l2 + y2 * m[0];
    l3 += y2 * m[1] + (x >> bits);
    lanes[2] = x & mask;
    uint64_t y3 = ((l3 & mask) * k0) & step3;
    x = l3 + y3 * m[0];
    lanes[3] = x & mask;
    *carry = x >> bits;
    y[0] = y0;
    y[1] = y1;
    y[2] = y2;
    y[3] = y3;
}

// The registers g + 2 to g + groups of a multiplication: group g's rows of
// m and of b. Register g + j is window lanes 4j on entry and 4(j - shift)
// on return.
static inline __attribute__((always_inline)) void
multiply_registers(uint64_t *window, const uint64_t *a, const uint64_t *m,
                   const rsa_avx2_lanes y[4], const rsa_avx2_lanes digit[4], size_t groups,
                   size_t shift) {
    for (size_t j = 2; j <= groups; j++) {
        rsa_avx2_lanes acc = lanes_load(window + 4 * j);
        acc = add_rows(acc, m, y, j);
        acc = add_rows(acc, a, digit, j);
        lanes_store(window + 4 * (j - shift), acc);
    }
}

// The registers g + 2 to g + groups of a square: group g's rows of m, and
// its rows of a from offset g up, which the three loops split at the
// offsets where the pattern of its multipliers changes. The window moves
// as in multiply_registers.
static inline __attribute__((always_inline)) void
square_registers(uint64_t *window, const uint64_t *a, const uint64_t *m, const rsa_avx2_lanes y[4],
                 const rsa_avx2_lanes digit[4], const rsa_avx2_lanes twice[4], size_t g,
                 size_t groups, size_t shift) {
    size_t j = 2;
    for (; j < g && j <= groups; j++) {
        rsa_avx2_lanes acc = lanes_load(window + 4 * j);
        lanes_store(window + 4 * (j - shift), add_rows(acc, m, y, j));
    }
    for (; j < g + 2 && j <= groups; j++) {
        rsa_avx2_lanes acc = lanes_load(window + 4 * j);
        acc = add_rows(acc, m, y, j);
        lanes_store(window + 4 * (j - shift), add_square_rows(acc, a, digit, twice, g, j));
    }
    for (; j <= groups; j++) {
        rsa_avx2_lanes acc = lanes_load(window + 4 * j);
        acc = add_rows(acc, m, y, j);
        lanes_store(window + 4 * (j - shift), add_rows(acc, a, twice, j));
    }
}

// Group g of a product, on the window that holds registers g to g + groups:
// y holds the group's y's on entry and the next group's on return, and
// *carry the carry into the next register. It adds the group's rows to
// register g + 1, runs the next group's triangle on it, and then adds the
// group's rows to the registers above. Each register moves down one
// register of the window, except in the last group, which writes in
// place.
static inline __attribute__((always_inline)) void
product_group(uint64_t *window, const uint64_t *a, const uint64_t *b, const rsa_avx2_modulus *mod,
              uint64_t y[4], uint64_t *carry, size_t g, unsigned bits, int square) {
    size_t groups = mod->groups;
    size_t next = g + 1;
    size_t shift = next < groups ? 1 : 0;
    const uint64_t mask = ((uint64_t)1 << bits) - 1;
    rsa_avx2_lanes y_lanes[4];
    rsa_avx2_lanes digit[4];
    broadcast_four(y_lanes, y, mask);
    broadcast_four(digit, b + PAD + 4 * g, mask);
    rsa_avx2_lanes twice[4];
    if (square) {
        broadcast_twice_four(twice, b + PAD + 4 * g, mask);
    }
    rsa_avx2_lanes acc = lanes_load(window + 4);
    acc = add_rows(acc, mod->digits, y_lanes, 1);
    if (square) {
        // A square's next group adds nothing at its own register.
        acc = add_square_rows(acc, a, digit, twice, g, 1);
    } else {
        acc = add_rows(acc, a, digit, 1);
        if (next < groups) {
            rsa_avx2_lanes next_digit[4];
            broadcast_four(next_digit, b + PAD + 4 * next, mask);
            acc = add_rows(acc, a, next_digit, 0);
        }
    }
    if (next < groups) {
        // The triangle runs on a copy of the register in this frame, which
        // no other pointer here can name, so the compiler keeps its lanes
        // in registers. Only the last triangle's lanes are read again:
        // they hold the result's digits from n up, and go to the window's
        // register 0.
        _Alignas(32) uint64_t lanes[4];
        lanes_store(lanes, acc);
        triangle(lanes, carry, y, mod, next, bits);
        if (next + 1 == groups) {
            memcpy(window, lanes, sizeof lanes);
        }
    } else {
        lanes_store(window + 4, acc);
    }
    if (square) {
        square_registers(window, a, mod->digits, y_lanes, digit, twice, g, groups, shift);
    } else {
        multiply_registers(window, a, mod->digits, y_lanes, digit, groups, shift);
    }
}

// out = a * b / R' plus m or nothing, below 2m (see the bound above), as a
// number, for D = bits: its n digits each below 2^bits. square says b is
// a. out holds a number's layout on entry, with zeros in its PAD lanes
// and from digit n up, and may be a or b: it is written after the last
// read of both. Each copy below fixes bits and square, so that the
// compiler folds them.
static inline __attribute__((always_inline)) void product_core(uint64_t *out, const uint64_t *a,
                                                               const uint64_t *b,
                                                               const rsa_avx2_modulus *mod,
                                                               unsigned bits, int square) {
    size_t groups = mod->groups;
    size_t n = mod->digit_count;
    _Alignas(32) uint64_t window[WINDOW_LANES];
    CH_ASSERT(groups >= 2 && groups <= GROUPS_MAX && n > 4 * (groups - 1) && n <= 4 * groups);
    memset(window, 0, 4 * (groups + 1) * sizeof(uint64_t));
    uint64_t y[4];
    uint64_t carry = 0;
    // Register 0: group 0's rows of b there, then its triangle, on a copy
    // of the register as in product_group.
    const uint64_t mask = ((uint64_t)1 << bits) - 1;
    rsa_avx2_lanes digit[4];
    broadcast_four(digit, b + PAD, mask);
    rsa_avx2_lanes first;
    if (square) {
        rsa_avx2_lanes twice[4];
        broadcast_twice_four(twice, b + PAD, mask);
        first = add_square_rows(lanes_zero(), a, digit, twice, 0, 0);
    } else {
        first = add_rows(lanes_zero(), a, digit, 0);
    }
    _Alignas(32) uint64_t lanes[4];
    lanes_store(lanes, first);
    triangle(lanes, &carry, y, mod, 0, bits);
    for (size_t g = 0; g < groups; g++) {
        product_group(window, a, b, mod, y, &carry, g, bits, square);
    }
    // The window holds registers groups - 1 to 2 groups - 1, so the sum's
    // lane 4 groups, which takes the last triangle's carry, is its lane 4,
    // and the sum's lane n is its lane n - 4(groups - 1), from 1 to 4.
    window[4] += carry;
    const uint64_t *result = window + n - 4 * (groups - 1);
    // One pass of carries makes the digits of the sum's lanes n to 2n - 1,
    // the result. The carry out of lane 2n - 1 is zero, because the result
    // is below 2m, which is below 2^(bits * n).
    uint64_t moved = 0;
    for (size_t p = 0; p < n; p++) {
        uint64_t value = result[p] + moved;
        out[PAD + p] = value & mask;
        moved = value >> bits;
    }
}

// The four copies of the product, each a frame of its own: the compiler
// may not inline one into its caller, whose frame holds numbers of its own
// (lint-stack).
static __attribute__((noinline)) void multiply_28(uint64_t *out, const uint64_t *a,
                                                  const uint64_t *b, const rsa_avx2_modulus *mod) {
    product_core(out, a, b, mod, 28, 0);
}

static __attribute__((noinline)) void square_28(uint64_t *out, const uint64_t *a,
                                                const rsa_avx2_modulus *mod) {
    product_core(out, a, a, mod, 28, 1);
}

#if RSA_MONT64_WORDS_MAX > 48
static __attribute__((noinline)) void multiply_27(uint64_t *out, const uint64_t *a,
                                                  const uint64_t *b, const rsa_avx2_modulus *mod) {
    product_core(out, a, b, mod, 27, 0);
}

static __attribute__((noinline)) void square_27(uint64_t *out, const uint64_t *a,
                                                const rsa_avx2_modulus *mod) {
    product_core(out, a, a, mod, 27, 1);
}
#endif

// The multiplication in the copy for the modulus's digit width. Below the
// 512-byte bound every modulus takes 28 bits.
static void multiply(uint64_t *out, const uint64_t *a, const uint64_t *b,
                     const rsa_avx2_modulus *mod) {
#if RSA_MONT64_WORDS_MAX > 48
    if (mod->bits == 27) {
        multiply_27(out, a, b, mod);
        return;
    }
#endif
    multiply_28(out, a, b, mod);
}

// The square in the copy for the modulus's digit width.
static void square(uint64_t *out, const uint64_t *a, const rsa_avx2_modulus *mod) {
#if RSA_MONT64_WORDS_MAX > 48
    if (mod->bits == 27) {
        square_27(out, a, mod);
        return;
    }
#endif
    square_28(out, a, mod);
}

// power = base * power / R' plus m or nothing, for base the len big-endian
// bytes at base, len <= 8k. base's words and digits live in this frame
// alone, which the compiler may not inline, and so does the last step's
// words in write_result's: rsa_avx2_public's frame holds two numbers, the
// modulus and the power, inside lint-stack's budget.
static __attribute__((noinline)) void multiply_by_base(uint64_t *power, const uint8_t *base,
                                                       size_t len, size_t k,
                                                       const rsa_avx2_modulus *modulus) {
    uint64_t words[RSA_MONT64_WORDS_MAX];
    _Alignas(32) uint64_t base_digits[NUMBER_LANES];
    rsa_mont64_from_bytes(words, k, base, len);
    words_to_digits(base_digits, words, k, modulus->digit_count, modulus->bits);
    multiply(power, base_digits, power, modulus);
}

// out = the len big-endian bytes of power less m once, for power below 2m.
static __attribute__((noinline)) void write_result(uint8_t *out, size_t len, const uint64_t *power,
                                                   const rsa_avx2_modulus *modulus,
                                                   const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    // k words and the word above them, which digits_to_words writes.
    uint64_t words[RSA_MONT64_WORDS_MAX + 1];
    digits_to_words(words, k, power, modulus->digit_count, modulus->bits);
    rsa_mont64_reduce_once_with_top(words, words, words[k], mod);
    rsa_mont64_to_bytes(out, len, words);
}

void rsa_avx2_public(uint8_t *out, const uint8_t *base, size_t len, const rsa_mont64_modulus *mod,
                     const uint64_t *digit_r2) {
    size_t k = mod->words;
    CH_ASSERT(k >= RSA_AVX2_WORDS_MIN && k <= RSA_MONT64_WORDS_MAX && len <= 8 * k);
    rsa_avx2_modulus modulus;
    modulus_from_words(&modulus, mod);
    _Alignas(32) uint64_t power[NUMBER_LANES];
    words_to_digits(power, digit_r2, k, modulus.digit_count, modulus.bits);

    // base is below 2^(64k), which is below R' / 4, and digit_r2 below m.
    // Each square's operand is below 2m. The last product's base * power
    // / R' is below 2m / 4, so it too is below 2m. base is read again for
    // the last product, before out is written.
    multiply_by_base(power, base, len, k, &modulus);
    for (int i = 0; i < 16; i++) {
        square(power, power, &modulus);
    }
    multiply_by_base(power, base, len, k, &modulus);
    write_result(out, len, power, &modulus, mod);
}

#ifndef CH_RSA_AVX2_MODEL
#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif
#endif

#endif // CH_CPU_RUNTIME && (__x86_64__ || CH_RSA_AVX2_MODEL)
