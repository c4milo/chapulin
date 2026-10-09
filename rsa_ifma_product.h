// The pieces of the almost-Montgomery product in radix 2^52 that both
// AVX-512 IFMA kernels run: rsa_ifma.c's public operation and
// rsa_ifma_sign.c's two exponentiations of a signature
// (docs/decisions.md 119 and 120). They are one text, here, so that the
// two kernels cannot differ in a round, in the carry that ends a product
// or in the conversions between 64-bit words and 52-bit digits.
//
// Only rsa_ifma.c and rsa_ifma_sign.c include this file, after the lane
// operations: rsa_ifma_lanes.h, between the attribute push that turns
// AVX-512F and AVX-512 IFMA on and its pop, or test/rsa_ifma_model_lanes.h
// in a unit that defines CH_RSA_IFMA_MODEL. So every function here
// carries the target of the file that includes it, and each file holds
// its own copy of the compiled code. test/widemul-builds.sh requires that
// no other root source includes it.
//
// The product. For n digits and R' = 2^(52n), it writes a * b / R' mod m
// in n rounds. Round i adds a * b[i] and quotient * m to a running sum
// and divides the sum by 2^52, where quotient is the digit that makes the
// sum's digit 0 zero, so the division drops no set bit. VPMADD52LUQ adds
// bits 51..0 of eight digit products to eight lanes, and VPMADD52HUQ adds
// bits 103..52, which belong one digit higher. So a round adds the low
// halves, moves every lane down one lane, which is the division, and then
// adds the high halves. The lanes carry nothing into each other during
// the rounds: a round adds four pieces below 2^52 to each lane, so after
// 79 rounds, the most, a lane is below 2^61, and normalize_digits carries
// once at the end. Digit 0 is the exception, because its carry decides
// the next round's quotient. A scalar word, digit_zero, holds it with
// every carry into it: each round adds to it the lane that moves into
// lane 0, and at the end it replaces lane 0 of the first register.
//
// The result is not reduced below m: it is below a * b / R' + m, so below
// 2m when a is below R' and b below m, and below 2m when a and b are both
// below 2m and 4m <= R', which RSA_IFMA_DIGIT_COUNT gives (rsa_ifma.h).
//
// Every branch and every memory index here depends on a word count, a
// digit count, a register count, a digit's index or a round's index, and
// normalize_digits chooses its lanes by a mask register.
//
// normalize_digits, add_round and finish_product ask the compiler to
// inline them into each copy of the product, so that each copy's loops
// run a constant count over its registers. gcc does not expand a macro in
// a pragma, so each loop over registers says #pragma GCC unroll 16, which
// covers every count either file holds.
#ifndef CH_RSA_IFMA_PRODUCT_H
#define CH_RSA_IFMA_PRODUCT_H

#include <stddef.h>
#include <stdint.h>

#include "ct.h"

// Eight digits to a 512-bit register.
#define DIGITS_PER_REGISTER ((size_t)8)

// A digit's 52 bits.
#define DIGIT_MASK ((UINT64_C(1) << 52) - 1)

// values[index] for an index below count, and 0 from count up. The index
// is public.
static uint64_t value_at_or_zero(const uint64_t *values, size_t count, size_t index) {
    return index < count ? values[index] : 0;
}

// digits[0..lane_count) = the number in words[0..word_count), which must
// be below 2^(52 * digit_count): digit_count digits of 52 bits, then
// zeros. Digit j is bits 52j to 52j + 51 of the number. They start at bit
// offset = 52j mod 64 of word 52j / 64 and run into the next word when
// offset is above 12. The next word's shift left by 64 - offset is two
// shifts, so that an offset of 0 shifts that word out whole, where one
// shift by 64 would be undefined.
static void words_to_digits(uint64_t *digits, const uint64_t *words, size_t word_count,
                            size_t digit_count, size_t lane_count) {
    for (size_t j = 0; j < digit_count; j++) {
        size_t bit = 52 * j;
        size_t index = bit / 64;
        unsigned offset = (unsigned)(bit % 64);
        uint64_t low = value_at_or_zero(words, word_count, index) >> offset;
        uint64_t high = value_at_or_zero(words, word_count, index + 1) << (63 - offset) << 1;
        digits[j] = (low | high) & DIGIT_MASK;
    }
    for (size_t j = digit_count; j < lane_count; j++) {
        digits[j] = 0;
    }
}

// words[0..word_count] = the number in digits[0..digit_count), each digit
// below 2^52: word_count words and the word above them, which must hold
// the rest of the number. Word w starts at bit 64w, which is bit offset
// of digit j = 64w / 52, with offset below 52. The word takes digit j from
// that bit up, digit j + 1 at bit 52 - offset, and digit j + 2 at bit
// 104 - offset where that is below 64, which is where offset is above 40.
static void digits_to_words(uint64_t *words, size_t word_count, const uint64_t *digits,
                            size_t digit_count) {
    for (size_t w = 0; w <= word_count; w++) {
        size_t j = 64 * w / 52;
        size_t offset = 64 * w - 52 * j;
        uint64_t word = value_at_or_zero(digits, digit_count, j) >> offset;
        word |= value_at_or_zero(digits, digit_count, j + 1) << (52 - offset);
        if (offset > 40) {
            word |= value_at_or_zero(digits, digit_count, j + 2) << (104 - offset);
        }
        words[w] = word;
    }
}

// Carries each lane's bits above 52 into the lane above, so that every
// digit is below 2^52, and drops the carry out of the top lane: the lanes
// then hold the number they held modulo 2^(52 * 8 * registers). A
// product's number is below 2m, which is below 2^(52n), so for a product
// that carry is zero.
//
// A lane below 2^64 carries less than 2^12, so one pass of those carries
// leaves each lane below 2^52 + 2^12. A second pass carries single bits.
// A lane above 2^52 - 1 sends a carry, and a lane at 2^52 - 1 sends one on
// when one arrives. generate marks the first kind and propagate the
// second, one mask bit per lane. The lanes that receive a carry are then
// ((generate << 1) + propagate) XOR propagate, an addition over the bits
// of every register, eight bits at a time from register 0 up, with the
// carry out of each eight bits added to the next. Each lane that receives
// one adds 1 and keeps its low 52 bits.
static inline __attribute__((always_inline)) void normalize_digits(rsa_ifma_lanes *sum,
                                                                   size_t registers) {
    const rsa_ifma_lanes mask = lanes_broadcast(DIGIT_MASK);
    const rsa_ifma_lanes one = lanes_broadcast(1);
    rsa_ifma_lanes below = lanes_zero(); // the carries of the register below
#pragma GCC unroll 16
    for (size_t i = 0; i < registers; i++) {
        rsa_ifma_lanes carries = lanes_shift_right_52(sum[i]);
        sum[i] = lanes_add(lanes_and(sum[i], mask), lanes_up_one(carries, below));
        below = carries;
    }
    unsigned generate_from_below = 0;
    unsigned carry_from_below = 0;
#pragma GCC unroll 16
    for (size_t i = 0; i < registers; i++) {
        unsigned generate = lanes_above(sum[i], mask);
        unsigned propagate = lanes_equal(sum[i], mask);
        unsigned shifted = ((generate << 1) | generate_from_below) & 0xffU;
        generate_from_below = generate >> 7;
        unsigned total = shifted + propagate + carry_from_below;
        carry_from_below = total >> 8;
        rsa_ifma_lane_bits receives = (rsa_ifma_lane_bits)((total ^ propagate) & 0xffU);
        sum[i] = lanes_and(lanes_add_where(sum[i], receives, sum[i], one), mask);
    }
}

// One round of the product: sum = (sum + a * b_digit + quotient * m) /
// 2^52, for the quotient below 2^52 that makes the sum's digit 0 zero.
// digit_zero holds that digit with every carry into it. Both products by
// digit 0 run in scalar code first, on ct_mul128, because the quotient
// depends on them. m is the modulus in digits, then zeros up to the
// registers' lanes, and m0inv is -m^-1 mod 2^52, so quotient * m[0] is
// the negative of the sum's digit 0 modulo 2^52.
static inline __attribute__((always_inline)) void add_round(rsa_ifma_lanes *sum,
                                                            uint64_t *digit_zero, const uint64_t *a,
                                                            uint64_t b_digit, const uint64_t *m,
                                                            uint64_t m0inv, size_t registers) {
    ct_u128 low = ct_mul128(a[0], b_digit) + *digit_zero;
    uint64_t quotient = (uint64_t)ct_mul128((uint64_t)low, m0inv) & DIGIT_MASK;
    low += ct_mul128(m[0], quotient);
    *digit_zero = (uint64_t)(low >> 52);
    rsa_ifma_lanes b_lanes = lanes_broadcast(b_digit);
    rsa_ifma_lanes quotient_lanes = lanes_broadcast(quotient);
    // Bits 51..0 of each product, in the lane of its digit.
#pragma GCC unroll 16
    for (size_t j = 0; j < registers; j++) {
        sum[j] = lanes_multiply_add_low(sum[j], lanes_load(a + 8 * j), b_lanes);
    }
#pragma GCC unroll 16
    for (size_t j = 0; j < registers; j++) {
        sum[j] = lanes_multiply_add_low(sum[j], lanes_load(m + 8 * j), quotient_lanes);
    }
    // The division by 2^52: each lane moves down one, lane 0 of each
    // register to lane 7 of the register below, and 0 enters the top lane.
    // Lane 0 of the first register leaves, and digit_zero, which holds it
    // with its carry, takes the lane that moves into its place.
#pragma GCC unroll 16
    for (size_t j = 0; j + 1 < registers; j++) {
        sum[j] = lanes_down_one(sum[j + 1], sum[j]);
    }
    sum[registers - 1] = lanes_down_one(lanes_zero(), sum[registers - 1]);
    *digit_zero += lanes_first(sum[0]);
    // Bits 103..52 of each product, one digit above its low bits, which is
    // the lane of the product's digit now that the lanes have moved.
#pragma GCC unroll 16
    for (size_t j = 0; j < registers; j++) {
        sum[j] = lanes_multiply_add_high(sum[j], lanes_load(a + 8 * j), b_lanes);
    }
#pragma GCC unroll 16
    for (size_t j = 0; j < registers; j++) {
        sum[j] = lanes_multiply_add_high(sum[j], lanes_load(m + 8 * j), quotient_lanes);
    }
}

// The end of a product after its last round: digit_zero back in lane 0 of
// the first register, one normalize_digits, and the lanes stored to out,
// 8 * registers words.
static inline __attribute__((always_inline)) void
finish_product(uint64_t *out, rsa_ifma_lanes *sum, uint64_t digit_zero, size_t registers) {
    sum[0] = lanes_replace_first(sum[0], digit_zero);
    normalize_digits(sum, registers);
#pragma GCC unroll 16
    for (size_t j = 0; j < registers; j++) {
        lanes_store(out + 8 * j, sum[j]);
    }
}

#endif
