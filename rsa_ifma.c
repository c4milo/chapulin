// RSA's public operation on AVX-512 IFMA (rsa_ifma.h): base^65537 mod m,
// on numbers in digits of 52 bits, eight digits to a 512-bit register.
//
// The product is the almost-Montgomery multiplication of OpenSSL's
// rsaz-2k-avx512, rsaz-3k-avx512 and rsaz-4k-avx512, in radix 2^52. For n
// digits and R' = 2^(52n), it writes a * b / R' mod m in n rounds. Round
// i adds a * b[i] and quotient * m to a running sum and divides the sum
// by 2^52, where quotient is the digit that makes the sum's digit 0 zero,
// so the division drops no set bit. VPMADD52LUQ adds bits 51..0 of eight
// digit products to eight lanes, and VPMADD52HUQ adds bits 103..52, which
// belong one digit higher. So a round adds the low halves, moves every
// lane down one lane, which is the division, and then adds the high
// halves. The lanes carry nothing into each other during the rounds: a
// round adds four pieces below 2^52 to each lane, so after 79 rounds, the
// most, a lane is below 2^61, and normalize_digits carries once at the
// end. Digit 0 is the exception, because its carry decides the next
// round's quotient. A scalar word, digit_zero, holds it with every carry
// into it: each round adds to it the lane that moves into lane 0, and at
// the end it replaces lane 0 of the first register.
//
// The result is not reduced below m: it is below a * b / R' + m, so below
// 2m when a is below R' and b below m, and below 2m when a and b are both
// below 2m and 4m <= R', which RSA_IFMA_DIGIT_COUNT gives.
//
// rsa_ifma_public runs rsa_mont64_public's exponentiation on that
// product. The first product, of base and digit_r2 = R'^2 mod m, writes
// base * R' mod m. Sixteen squares write base^65536 * R' mod m, and the
// last product, by base itself, divides by R': base^65537 mod m, below
// 2m, which one subtraction of m ends.
//
// Every branch and every memory index here depends on the word count, the
// digit count, the register count, a digit's index or a round's index,
// and normalize_digits chooses its lanes by a mask register. The inputs
// are public all the same, and nothing is wiped: the compiler keeps
// 512-bit registers in stack slots that no wipe can name, which is why
// only verification calls this file (rsa_ifma.h).
#include "rsa_ifma.h"

// The whole file compiles only in a host object on x86-64, or in a test
// unit that defines CH_RSA_IFMA_MODEL (rsa_ifma.h).
#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_RSA_IFMA_MODEL))

#include "ch_assert.h"
#include "ct.h"

#ifdef CH_RSA_IFMA_MODEL
// Each lane operation in portable C (test/rsa_ifma_model_lanes.h), which
// only a build with -Itest finds.
#include "rsa_ifma_model_lanes.h"
#else
#include <immintrin.h>

// Every function from here to the pop at the end of this file carries the
// target attribute that turns AVX-512F and AVX-512 IFMA on, and no
// function outside it does, as in chacha20_avx2.c. clang applies it
// through one attribute push; gcc's target pragma sets it for each
// function defined after it, until the pop. make compiles the object with
// no instruction flag, and build.zig adds only the evex512 feature, which
// turns on no instruction (build.zig's withEvex512). So only these
// functions hold AVX-512 instructions, and rsa_mont.c calls
// rsa_ifma_public only where the caller's CH_CPU_AVX512_IFMA bit says the
// CPU has them.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx512f,avx512ifma"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx512f,avx512ifma")
#endif

#include "rsa_ifma_lanes.h"
#endif

// normalize_digits, add_round and almost_montgomery_product_core below
// ask the compiler to inline them into each copy of the product, so that
// each copy's loops run a constant count over its registers. Under the
// pinned clang at -O2 for x86-64, the copies of the 384-byte build then
// keep a product's running sum, at most eight registers, in the 32 vector
// registers, and the copies of the 512-byte build, with up to ten, store
// some of them on the stack (docs/decisions.md 119).
//
// Eight digits to a 512-bit register, and the most lanes a number takes.
#define DIGITS_PER_REGISTER ((size_t)8)
#define LANE_COUNT_MAX (DIGITS_PER_REGISTER * RSA_IFMA_REGISTERS_MAX)

// A digit's 52 bits.
#define DIGIT_MASK ((UINT64_C(1) << 52) - 1)

// rsa.h's two bounds, 384 and 512 bytes, give 8 and 10 registers, and
// RSA_IFMA_WORDS_MIN gives 5. almost_montgomery_product below has a copy
// for each count from 5 to the bound. gcc does not expand a macro in a
// pragma, so each loop over registers says #pragma GCC unroll 16, which
// covers both bounds.
_Static_assert(RSA_IFMA_REGISTERS_MAX == 8 || RSA_IFMA_REGISTERS_MAX == 10,
               "almost_montgomery_product has copies for 8 or 10 registers at the most");
_Static_assert((RSA_IFMA_DIGIT_COUNT(RSA_IFMA_WORDS_MIN) + 7) / 8 == 5,
               "almost_montgomery_product's first copy is for 5 registers");

// What each product reads of the modulus. rsa_ifma_public writes it on
// its own stack at the start of each call, from rsa_mont64.c's record of
// the same modulus. No session stores it, and it holds nothing secret.
typedef struct {
    _Alignas(64) uint64_t digits[LANE_COUNT_MAX]; // m in digit_count digits, then zeros
    uint64_t m0inv;                               // -m^-1 mod 2^52
    size_t digit_count;                           // n = rsa_ifma_digit_count(k)
    size_t registers;                             // ceil(n / 8)
} rsa_ifma_modulus;

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
// depends on them. m0inv is -m^-1 mod 2^52, so quotient * m[0] is the
// negative of the sum's digit 0 modulo 2^52.
static inline __attribute__((always_inline)) void
add_round(rsa_ifma_lanes *sum, uint64_t *digit_zero, const uint64_t *a, uint64_t b_digit,
          const rsa_ifma_modulus *modulus, size_t registers) {
    const uint64_t *m = modulus->digits;
    ct_u128 low = ct_mul128(a[0], b_digit) + *digit_zero;
    uint64_t quotient = (uint64_t)ct_mul128((uint64_t)low, modulus->m0inv) & DIGIT_MASK;
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

// out = a * b / 2^(52n) mod m, for n = modulus->digit_count: n digits
// each below 2^52, then zero in each lane up to 8 * registers. It is below
// 2m where a is below 2^(52n) and b below m, or both are below 2m. a and b
// are in digits below 2^52, and a is zero from digit n up. out may be a or
// b: it is written after the last read of both.
//
// The lanes from n up stay zero through the rounds: a's and m's digits
// there are zero, and each lane takes only what moves down from the lane
// above it. A sum below 2^(52n) leaves digit n - 1 below 2^52, so
// normalize_digits writes zero there too.
static inline __attribute__((always_inline)) void
almost_montgomery_product_core(uint64_t *out, const uint64_t *a, const uint64_t *b,
                               const rsa_ifma_modulus *modulus, size_t registers) {
    rsa_ifma_lanes sum[RSA_IFMA_REGISTERS_MAX];
#pragma GCC unroll 16
    for (size_t j = 0; j < registers; j++) {
        sum[j] = lanes_zero();
    }
    uint64_t digit_zero = 0;
    for (size_t i = 0; i < modulus->digit_count; i++) {
        add_round(sum, &digit_zero, a, b[i], modulus, registers);
    }
    sum[0] = lanes_replace_first(sum[0], digit_zero);
    normalize_digits(sum, registers);
#pragma GCC unroll 16
    for (size_t j = 0; j < registers; j++) {
        lanes_store(out + 8 * j, sum[j]);
    }
}

// One copy of the product for each register count, so that each copy's
// loops over registers have a constant count, which the compiler unrolls
// and keeps in vector registers.
static void almost_montgomery_product_5(uint64_t *out, const uint64_t *a, const uint64_t *b,
                                        const rsa_ifma_modulus *modulus) {
    almost_montgomery_product_core(out, a, b, modulus, 5);
}

static void almost_montgomery_product_6(uint64_t *out, const uint64_t *a, const uint64_t *b,
                                        const rsa_ifma_modulus *modulus) {
    almost_montgomery_product_core(out, a, b, modulus, 6);
}

static void almost_montgomery_product_7(uint64_t *out, const uint64_t *a, const uint64_t *b,
                                        const rsa_ifma_modulus *modulus) {
    almost_montgomery_product_core(out, a, b, modulus, 7);
}

static void almost_montgomery_product_8(uint64_t *out, const uint64_t *a, const uint64_t *b,
                                        const rsa_ifma_modulus *modulus) {
    almost_montgomery_product_core(out, a, b, modulus, 8);
}

#if RSA_IFMA_REGISTERS_MAX == 10
static void almost_montgomery_product_9(uint64_t *out, const uint64_t *a, const uint64_t *b,
                                        const rsa_ifma_modulus *modulus) {
    almost_montgomery_product_core(out, a, b, modulus, 9);
}

static void almost_montgomery_product_10(uint64_t *out, const uint64_t *a, const uint64_t *b,
                                         const rsa_ifma_modulus *modulus) {
    almost_montgomery_product_core(out, a, b, modulus, 10);
}
#endif

// The product, in the copy for the modulus's register count.
// modulus_from_words writes a count from 5 to RSA_IFMA_REGISTERS_MAX, and
// each has a case below; both bounds share every case up to 8. A count
// the default arm receives is outside that range, so its CH_ASSERT fails.
static void almost_montgomery_product(uint64_t *out, const uint64_t *a, const uint64_t *b,
                                      const rsa_ifma_modulus *modulus) {
    switch (modulus->registers) {
    case 5:
        almost_montgomery_product_5(out, a, b, modulus);
        break;
    case 6:
        almost_montgomery_product_6(out, a, b, modulus);
        break;
    case 7:
        almost_montgomery_product_7(out, a, b, modulus);
        break;
    case 8:
        almost_montgomery_product_8(out, a, b, modulus);
        break;
#if RSA_IFMA_REGISTERS_MAX == 10
    case 9:
        almost_montgomery_product_9(out, a, b, modulus);
        break;
    case 10:
        almost_montgomery_product_10(out, a, b, modulus);
        break;
#endif
    default:
        CH_ASSERT(modulus->registers >= 5 && modulus->registers <= RSA_IFMA_REGISTERS_MAX);
        break;
    }
}

// The product's record of mod's modulus: its digits, the low 52 bits of
// rsa_mont64.c's -m^-1 mod 2^64, which are -m^-1 mod 2^52, and the digit
// and register counts for its k words.
static void modulus_from_words(rsa_ifma_modulus *modulus, const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    modulus->digit_count = rsa_ifma_digit_count(k);
    modulus->registers = (modulus->digit_count + DIGITS_PER_REGISTER - 1) / DIGITS_PER_REGISTER;
    modulus->m0inv = mod->m0inv & DIGIT_MASK;
    words_to_digits(modulus->digits, mod->m, k, modulus->digit_count, LANE_COUNT_MAX);
}

void rsa_ifma_public(uint8_t *out, const uint8_t *base, size_t len, const rsa_mont64_modulus *mod,
                     const uint64_t *digit_r2) {
    size_t k = mod->words;
    CH_ASSERT(k >= RSA_IFMA_WORDS_MIN && k <= RSA_MONT64_WORDS_MAX && len <= 8 * k);
    rsa_ifma_modulus modulus;
    modulus_from_words(&modulus, mod);
    size_t lane_count = DIGITS_PER_REGISTER * modulus.registers;
    // k words and the word above them, which digits_to_words writes.
    uint64_t words[RSA_MONT64_WORDS_MAX + 1] = {0};
    _Alignas(64) uint64_t base_digits[LANE_COUNT_MAX];
    _Alignas(64) uint64_t power[LANE_COUNT_MAX];
    rsa_mont64_from_bytes(words, k, base, len);
    words_to_digits(base_digits, words, k, modulus.digit_count, lane_count);
    words_to_digits(power, digit_r2, k, modulus.digit_count, lane_count);

    // base is below 2^(64k), which is below R' / 4, and digit_r2 below m.
    // Each square's operands are below 2m. The last product's base * power
    // / R' is below 2m / 4, so it too is below 2m.
    almost_montgomery_product(power, base_digits, power, &modulus);
    for (int i = 0; i < 16; i++) {
        almost_montgomery_product(power, power, power, &modulus);
    }
    almost_montgomery_product(power, base_digits, power, &modulus);
    digits_to_words(words, k, power, modulus.digit_count);
    rsa_mont64_reduce_once_with_top(words, words, words[k], mod);
    rsa_mont64_to_bytes(out, len, words);
}

#ifndef CH_RSA_IFMA_MODEL
#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif
#endif

#endif // CH_CPU_RUNTIME && (__x86_64__ || CH_RSA_IFMA_MODEL)
