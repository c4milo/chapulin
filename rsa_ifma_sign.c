// RSA signing's two exponentiations on AVX-512 IFMA (rsa_ifma_sign.h).
//
// The product is rsa_ifma_product.h's almost-Montgomery multiplication in
// radix 2^52, R' = 2^(52n) for n digits, here over a prime: 20 digits in
// three registers for RSA-2048's 16-word primes, 21 in three for
// RSA-2112's 17, 30 in four for RSA-3072's 24 and 40 in five for
// RSA-4096's 32. Each product under one prime runs beside the same
// product under the other, round by round, so that the two chains of
// multiplications overlap.
//
// The exponentiation is rsa_sign64_power's fixed window of four bits on
// that product. The table holds base^i * R' mod m, or that plus m, for i
// from 0 to 15. Every product's result is below 2m, and so is every
// operand, which the product's bound covers because 4m <= R'.
//
// The domains. rsa_mont64.c's domain multiplies by R = 2^(64k); this one
// by R' = R * 2^spare, spare = 52n - 64k bits: 16 at 16 words, 4 at 17, 24
// at 24 and 32 at 32. A base in rsa_mont64.c's domain doubled spare times
// modulo m is the same base in this one, and so is R mod m, which is 1 in
// rsa_mont64.c's domain. The last product, by R mod m, divides by R' and
// multiplies by R: the power in rsa_mont64.c's domain, below 2m, which one
// subtraction under a mask ends.
//
// Every branch and every memory index depends on a word count, a digit
// count, a register count, an index or the exponent's length. table_select
// reads every entry and keeps one by masks, and every array a function
// here names that held a value computed from the key is wiped before it
// returns.
#include "rsa_ifma_sign.h"

// The whole file compiles only in a host object on x86-64, or in a test
// unit that defines CH_RSA_IFMA_MODEL (rsa_ifma_sign.h).
#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_RSA_IFMA_MODEL))

#include <string.h>

#include "ch_assert.h"
#include "ct.h"
#include "rsa_ifma.h"

// The wipe of the stack below the caller, in p256_wide_wipe.c's form. Its
// frame is the array. ct_wipe is compiled apart from it and takes the
// array's address, so the compiler keeps the array in memory and cannot
// delete the call. The pointer is a volatile object, so the compiler
// cannot tell which function the call runs and cannot compile it into
// rsa_ifma_sign_wipe_below, whose caller's frame the array must lie under.
// These three come before the target attribute below, so they hold no
// AVX-512 instruction.
static void wipe_frame(void) {
    uint8_t below[RSA_IFMA_SIGN_BELOW_LEN];
    ct_wipe(below, sizeof below);
}

static void (*const volatile wipe_frame_call)(void) = wipe_frame;

void rsa_ifma_sign_wipe_below(void) {
    wipe_frame_call();
}

#ifdef CH_RSA_IFMA_MODEL
// Each lane operation in portable C (test/rsa_ifma_model_lanes.h), which
// only a build with -Itest finds.
#include "rsa_ifma_model_lanes.h"
#else
#include <immintrin.h>

// Every function from here to the pop at the end of this file carries the
// target attribute that turns AVX-512F and AVX-512 IFMA on, as in
// rsa_ifma.c, and no function before it does.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx512f,avx512ifma"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx512f,avx512ifma")
#endif

#include "rsa_ifma_lanes.h"
#endif

#include "rsa_ifma_product.h"

// The fewest and the most registers of eight digits a prime takes, which
// the preprocessor reads, and the lanes of the most.
#define SIGN_REGISTERS_MIN ((RSA_IFMA_DIGIT_COUNT(RSA_IFMA_SIGN_WORDS_MIN) + 7) / 8)
#define SIGN_REGISTERS_MAX ((RSA_IFMA_DIGIT_COUNT(RSA_IFMA_SIGN_WORDS_MAX) + 7) / 8)
#define SIGN_LANES_MAX (DIGITS_PER_REGISTER * SIGN_REGISTERS_MAX)

// The bits of the exponent one step reads, and the powers the table holds
// for them, as in rsa_sign64.c.
#define WINDOW_BITS 4
#define TABLE_ENTRIES 16

// rsa.h's two bounds, 384 and 512 bytes, give primes of up to 24 and 32
// words: 4 and 5 registers. RSA_IFMA_SIGN_WORDS_MIN gives 3. The product
// has a copy for each count from 3 to the bound.
_Static_assert(SIGN_REGISTERS_MIN == 3, "product_pair's first copy is for 3 registers");
_Static_assert(SIGN_REGISTERS_MAX == 4 || SIGN_REGISTERS_MAX == 5,
               "product_pair has copies for 4 or 5 registers at the most");
_Static_assert(TABLE_ENTRIES == 1 << WINDOW_BITS,
               "the table holds one power for each window value");

// A prime as the product reads it, in digits. It is secret, and wiped.
typedef struct {
    _Alignas(64) uint64_t digits[SIGN_LANES_MAX]; // m in digit_count digits, then zeros
    uint64_t m0inv;                               // -m^-1 mod 2^52
    size_t digit_count;                           // n = RSA_IFMA_DIGIT_COUNT(k)
    size_t registers;                             // ceil(n / 8)
} sign_modulus;

// The base's powers 0 to 15 under one prime, each base^i * R' mod m or
// that plus m, in digits. A struct, so that table_select can take it as a
// pointer to const, as rsa_sign64.c's power_table is.
typedef struct {
    _Alignas(64) uint64_t powers[TABLE_ENTRIES][SIGN_LANES_MAX];
} sign_table;

// One prime's exponentiation: its record, its table, the running power,
// the entry the step read, and R mod m, the last product's factor. All in
// digits, and all secret.
typedef struct {
    sign_modulus modulus;
    sign_table table;
    _Alignas(64) uint64_t power[SIGN_LANES_MAX];
    _Alignas(64) uint64_t pick[SIGN_LANES_MAX];
    _Alignas(64) uint64_t r_mod_m[SIGN_LANES_MAX];
} sign_state;

// Two products, one under each prime, the round of one beside the same
// round of the other: out_p = a_p * b_p / R' mod p and out_q = a_q * b_q /
// R' mod q, each below twice its prime, for operands below twice their
// primes. The two primes have the same digit count, so one loop runs both.
// out_p may be a_p or b_p, and out_q a_q or b_q: each is written after the
// last read of both.
static inline __attribute__((always_inline)) void
pair_core(uint64_t *out_p, const uint64_t *a_p, const uint64_t *b_p, const sign_modulus *mod_p,
          uint64_t *out_q, const uint64_t *a_q, const uint64_t *b_q, const sign_modulus *mod_q,
          size_t registers) {
    rsa_ifma_lanes sum_p[SIGN_REGISTERS_MAX];
    rsa_ifma_lanes sum_q[SIGN_REGISTERS_MAX];
#pragma GCC unroll 16
    for (size_t j = 0; j < registers; j++) {
        sum_p[j] = lanes_zero();
        sum_q[j] = lanes_zero();
    }
    uint64_t zero_p = 0;
    uint64_t zero_q = 0;
    for (size_t i = 0; i < mod_p->digit_count; i++) {
        add_round(sum_p, &zero_p, a_p, b_p[i], mod_p->digits, mod_p->m0inv, registers);
        add_round(sum_q, &zero_q, a_q, b_q[i], mod_q->digits, mod_q->m0inv, registers);
    }
    finish_product(out_p, sum_p, zero_p, registers);
    finish_product(out_q, sum_q, zero_q, registers);
}

// One copy of the pair for each register count, so that each copy's loops
// over registers run a constant count, which the compiler unrolls and
// keeps in vector registers.
static void product_pair_3(uint64_t *out_p, const uint64_t *a_p, const uint64_t *b_p,
                           const sign_modulus *mod_p, uint64_t *out_q, const uint64_t *a_q,
                           const uint64_t *b_q, const sign_modulus *mod_q) {
    pair_core(out_p, a_p, b_p, mod_p, out_q, a_q, b_q, mod_q, 3);
}

static void product_pair_4(uint64_t *out_p, const uint64_t *a_p, const uint64_t *b_p,
                           const sign_modulus *mod_p, uint64_t *out_q, const uint64_t *a_q,
                           const uint64_t *b_q, const sign_modulus *mod_q) {
    pair_core(out_p, a_p, b_p, mod_p, out_q, a_q, b_q, mod_q, 4);
}

#if SIGN_REGISTERS_MAX == 5
static void product_pair_5(uint64_t *out_p, const uint64_t *a_p, const uint64_t *b_p,
                           const sign_modulus *mod_p, uint64_t *out_q, const uint64_t *a_q,
                           const uint64_t *b_q, const sign_modulus *mod_q) {
    pair_core(out_p, a_p, b_p, mod_p, out_q, a_q, b_q, mod_q, 5);
}
#endif

// The pair, in the copy for the primes' register count. state_setup
// writes a count from 3 to SIGN_REGISTERS_MAX, and each has a case below;
// both bounds share the cases for 3 and 4. A count the default arm
// receives is outside that range, so its CH_ASSERT fails.
static void product_pair(uint64_t *out_p, const uint64_t *a_p, const uint64_t *b_p,
                         const sign_modulus *mod_p, uint64_t *out_q, const uint64_t *a_q,
                         const uint64_t *b_q, const sign_modulus *mod_q) {
    switch (mod_p->registers) {
    case 3:
        product_pair_3(out_p, a_p, b_p, mod_p, out_q, a_q, b_q, mod_q);
        break;
    case 4:
        product_pair_4(out_p, a_p, b_p, mod_p, out_q, a_q, b_q, mod_q);
        break;
#if SIGN_REGISTERS_MAX == 5
    case 5:
        product_pair_5(out_p, a_p, b_p, mod_p, out_q, a_q, b_q, mod_q);
        break;
#endif
    default:
        CH_ASSERT(mod_p->registers >= 3 && mod_p->registers <= SIGN_REGISTERS_MAX);
        break;
    }
}

// All ones when bit is 1, all zeros when bit is 0, in rsa_sign64.c's form
// and for its reason.
static uint64_t mask_of_bit(uint64_t bit) {
    return (uint64_t)((int64_t)(bit << 63) >> 63);
}

// out = the table's power at digit i of the exponent e, counted from the
// most significant: the high half of byte i / 2 for an even i and the low
// half for an odd one. No memory index and no branch comes from the digit:
// each register's loop reads every entry and keeps one by a mask, which
// it writes through a volatile pointer and reads back before it uses it,
// as rsa_sign64.c's table_select does and for its reason. The digit is
// computed here, so no register of the caller holds it across a product.
// out's lanes from 8 * registers up are not written.
static void table_select(uint64_t *out, const sign_table *table, const uint8_t *e, size_t i,
                         size_t registers) {
    uint64_t digit = ((uint64_t)e[i >> 1] >> (WINDOW_BITS * (1 - (i & 1)))) & (TABLE_ENTRIES - 1);
    uint64_t kept = 0;
    volatile uint64_t *hidden = &kept;
    for (size_t j = 0; j < registers; j++) {
        rsa_ifma_lanes picked = lanes_zero();
        for (uint64_t entry = 0; entry < TABLE_ENTRIES; entry++) {
            uint64_t differ = ((entry ^ digit) + (TABLE_ENTRIES - 1)) >> WINDOW_BITS;
            *hidden = mask_of_bit(differ ^ 1);
            rsa_ifma_lanes mask = lanes_broadcast(*hidden);
            rsa_ifma_lanes power = lanes_load(table->powers[entry] + DIGITS_PER_REGISTER * j);
            picked = lanes_add(picked, lanes_and(power, mask));
        }
        lanes_store(out + DIGITS_PER_REGISTER * j, picked);
    }
    // The word ends on zero and not on the last entry's mask, which says
    // whether the digit was the last index.
    *hidden = 0;
}

// s's record of the prime in mod, R mod m in digits, and the table's
// first two entries, R' mod m and base * R' mod m, from rsa_mont64.c's
// record and the base in its domain. 1 in rsa_mont64.c's domain is R mod
// m, which one product of the plain 1 by r2 gives.
static void state_setup(sign_state *s, const uint64_t *base, const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    CH_ASSERT(k >= RSA_IFMA_SIGN_WORDS_MIN && k <= RSA_IFMA_SIGN_WORDS_MAX);
    size_t n = RSA_IFMA_DIGIT_COUNT(k);
    size_t registers = (n + DIGITS_PER_REGISTER - 1) / DIGITS_PER_REGISTER;
    size_t lanes = DIGITS_PER_REGISTER * registers;
    size_t spare = 52 * n - 64 * k;
    s->modulus.digit_count = n;
    s->modulus.registers = registers;
    s->modulus.m0inv = mod->m0inv & DIGIT_MASK;
    words_to_digits(s->modulus.digits, mod->m, k, n, SIGN_LANES_MAX);

    uint64_t one[RSA_IFMA_SIGN_WORDS_MAX] = {0};
    uint64_t scaled[RSA_IFMA_SIGN_WORDS_MAX];
    one[0] = 1;
    rsa_mont64_mont_mul(scaled, one, mod->r2, mod);
    words_to_digits(s->r_mod_m, scaled, k, n, lanes);
    for (size_t i = 0; i < spare; i++) {
        rsa_mont64_add(scaled, scaled, scaled, mod);
    }
    words_to_digits(s->table.powers[0], scaled, k, n, lanes);
    memcpy(scaled, base, k * sizeof(uint64_t));
    for (size_t i = 0; i < spare; i++) {
        rsa_mont64_add(scaled, scaled, scaled, mod);
    }
    words_to_digits(s->table.powers[1], scaled, k, n, lanes);
    ct_wipe(scaled, sizeof scaled);
}

// o = the power s holds, which the last product left in rsa_mont64.c's
// domain below 2m, in k words and reduced below m: digits_to_words writes
// the k words and the word above them, and one subtraction of m under a
// mask ends it.
static void state_finish(uint64_t *o, const sign_state *s, const rsa_mont64_modulus *mod) {
    uint64_t words[RSA_IFMA_SIGN_WORDS_MAX + 1];
    digits_to_words(words, mod->words, s->power, s->modulus.digit_count);
    rsa_mont64_reduce_once_with_top(o, words, words[mod->words], mod);
    ct_wipe(words, sizeof words);
}

void rsa_ifma_sign_power_pair(uint64_t *o_p, const uint64_t *base_p, const uint8_t *e_p,
                              const rsa_mont64_modulus *mod_p, uint64_t *o_q,
                              const uint64_t *base_q, const uint8_t *e_q,
                              const rsa_mont64_modulus *mod_q, size_t e_len) {
    CH_ASSERT(mod_p->words == mod_q->words);
    sign_state p;
    sign_state q;
    state_setup(&p, base_p, mod_p);
    state_setup(&q, base_q, mod_q);
    const sign_modulus *record_p = &p.modulus;
    const sign_modulus *record_q = &q.modulus;

    // powers[i] = base^i, for i from 2 to 15, from the two entries
    // state_setup wrote.
    for (size_t i = 2; i < TABLE_ENTRIES; i++) {
        product_pair(p.table.powers[i], p.table.powers[i - 1], p.table.powers[1], record_p,
                     q.table.powers[i], q.table.powers[i - 1], q.table.powers[1], record_q);
    }

    // The running powers start at 1. Each step raises them to the 16th
    // power and multiplies each by its base to its exponent's digit: two
    // steps for each byte of the exponents, so the step count is a
    // function of e_len alone.
    memcpy(p.power, p.table.powers[0], sizeof p.power);
    memcpy(q.power, q.table.powers[0], sizeof q.power);
    for (size_t i = 0; i < 2 * e_len; i++) {
        for (int square = 0; square < WINDOW_BITS; square++) {
            product_pair(p.power, p.power, p.power, record_p, q.power, q.power, q.power, record_q);
        }
        table_select(p.pick, &p.table, e_p, i, record_p->registers);
        table_select(q.pick, &q.table, e_q, i, record_q->registers);
        product_pair(p.power, p.power, p.pick, record_p, q.power, q.power, q.pick, record_q);
    }

    // Back to rsa_mont64.c's domain, and below each prime.
    product_pair(p.power, p.power, p.r_mod_m, record_p, q.power, q.power, q.r_mod_m, record_q);
    state_finish(o_p, &p, mod_p);
    state_finish(o_q, &q, mod_q);
    ct_wipe(&p, sizeof p);
    ct_wipe(&q, sizeof q);
}

#ifndef CH_RSA_IFMA_MODEL
#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif
#endif

#endif // CH_CPU_RUNTIME && (__x86_64__ || CH_RSA_IFMA_MODEL)
