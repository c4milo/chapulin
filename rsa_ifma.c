// RSA's public operation on AVX-512 IFMA (rsa_ifma.h): base^65537 mod m,
// on numbers in digits of 52 bits, eight digits to a 512-bit register.
//
// The product is the almost-Montgomery multiplication of OpenSSL's
// rsaz-2k-avx512, rsaz-3k-avx512 and rsaz-4k-avx512, in radix 2^52, whose
// round, end and conversions rsa_ifma_product.h holds for this file and
// for rsa_ifma_sign.c. For n digits and R' = 2^(52n), it writes
// a * b / R' mod m, below 2m when a is below R' and b below m, and below
// 2m when a and b are both below 2m and 4m <= R', which
// RSA_IFMA_DIGIT_COUNT gives.
//
// rsa_ifma_public runs rsa_mont64_public's exponentiation on that
// product. The first product, of base and digit_r2 = R'^2 mod m, writes
// base * R' mod m. Sixteen squares write base^65536 * R' mod m, and the
// last product, by base itself, divides by R': base^65537 mod m, below
// 2m, which one subtraction of m ends.
//
// Every branch and every memory index here depends on the word count, the
// digit count, the register count, a digit's index or a round's index,
// and normalize_digits chooses its lanes by a mask register. The file
// wipes nothing: the compiler keeps 512-bit registers in stack slots that
// no wipe written here can name. A verifier's inputs are public. The one
// caller whose input is not, rsa_sign64.c's check of a signature, wipes
// the stack below its frame and the vector registers after the call
// (rsa_ifma.h).
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

#include "rsa_ifma_product.h"

// almost_montgomery_product_core below asks the compiler to inline it, and
// rsa_ifma_product.h's pieces, into each copy of the product, so that each
// copy's loops run a constant count over its registers. Under the pinned
// clang at -O2 for x86-64, the copies of the 384-byte build then keep a
// product's running sum, at most eight registers, in the 32 vector
// registers, and the copies of the 512-byte build, with up to ten, store
// some of them on the stack (docs/decisions.md 119).
//
// The most lanes a number takes.
#define LANE_COUNT_MAX (DIGITS_PER_REGISTER * RSA_IFMA_REGISTERS_MAX)

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
        add_round(sum, &digit_zero, a, b[i], modulus->digits, modulus->m0inv, registers);
    }
    finish_product(out, sum, digit_zero, registers);
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
