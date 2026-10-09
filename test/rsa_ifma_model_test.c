// bin/rsa_ifma_model_test: rsa_ifma.c's kernel, compiled over the lane
// model (test/rsa_ifma_model.c), against rsa_mont64.c on every machine.
// The model is each AVX-512 instruction in portable C, so the kernel's own
// text runs here on any CPU, and bin/rsa_ifma_equiv_test holds the model
// to the instructions on a CPU that has them. The Makefile builds it at
// the 512-byte bound, where the kernel has copies of the product for 5 to
// 10 registers, and again as bin/rsa_ifma_model_test_384 at the 384-byte
// bound of a server object, where it has copies for 5 to 8.
//
// At every word count from RSA_IFMA_WORDS_MIN to RSA_MONT64_WORDS_MAX, so
// at every register count the kernel has a copy for, under random odd
// moduli with the top bit set, 2^(64k) - 1, 2^(64k - 1) + 1 and, at an
// even count, test/rsa_equiv_test.c's (B^(k + 1) + 1) / (B + 1), it
// compares:
//
//   - rsa_vp1_cpu under CH_CPU_AVX512_IFMA, which takes the kernel, and
//     under CH_CPU_PROBED alone, which takes rsa_mont64.c, with rsa_vp1,
//     which takes rsa_mont64.c, for the signatures 0, 1, m - 1 and random
//     values below m. 0, 1 and m - 1 are their own 65537th powers, so
//     those three are checked against the known answer too. Under the bit
//     rsa_vp1_cpu must call rsa_ifma_public once, and without it never
//     (rsa_ifma_model_public_calls);
//   - rsa_ifma_public with rsa_mont64_public for bases at or above m,
//     which the verifiers never pass and the call takes: m, the top word
//     at all ones and random words below it, and 2^(64k) - 1. Its digit_r2
//     comes from doublings, which share nothing with rsa_mont.c's division;
//   - each product of rsa_ifma_public's chain for a random base: every
//     digit below 2^52, every lane from digit n up zero and the number
//     below 2m, and the chain's last number, less m once, against
//     rsa_mont64_public's;
//   - products of operands up to 2m, the most a square takes: the same
//     digit checks, and the number, less m once, against the product of
//     the operands less m.
//
// rsa_vp1_cpu under the bit must also write rsa_vp1's bytes, and never
// call rsa_ifma_public, for moduli the dispatch refuses: an even one, one
// whose top bit is clear, one of 31 words and one of 260 bytes.
// normalize_digits runs alone on lanes chosen for its carries, which a
// random product almost never gives it: the number they hold must stay
// the same modulo the lanes' 2^(52 * lanes) and every digit must fall
// below 2^52.
#define CH_RSA_IFMA_MODEL 1

#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "cpu_cfg.h"
#include "rsa_ifma.h"
#include "rsa_ifma_inputs.h"
#include "rsa_ifma_test.h"
#include "rsa_mont64.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

_Static_assert(RSA_MONT64_WORDS_MAX == 48 || RSA_MONT64_WORDS_MAX == 64,
               "bin/rsa_ifma_model_test builds at the 512-byte bound and "
               "bin/rsa_ifma_model_test_384 at the 384-byte bound");

#define WORDS_MAX RSA_MONT64_WORDS_MAX
#define DIGIT_MASK ((UINT64_C(1) << 52) - 1)
#define IFMA_CPU (CH_CPU_PROBED | CH_CPU_AVX512_IFMA)
#define NORMALIZE_CASES 20000

static int failures = 0;
static unsigned long compared = 0;

static void check(int ok, const char *what, size_t k) {
    compared++;
    if (!ok) {
        failures++;
        (void)fprintf(stderr, "FAIL %s, at %zu words\n", what, k);
    }
}

// The digits of a product at k words: each below 2^52, zero from digit n
// up to the last lane of its registers, and the number below 2m.
static void check_product_digits(const char *what, const uint64_t *digits,
                                 const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    size_t digit_count = rsa_ifma_digit_count(k);
    size_t lane_count = 8 * ((digit_count + 7) / 8);
    int ok = 1;
    for (size_t j = 0; j < digit_count; j++) {
        ok &= digits[j] <= DIGIT_MASK;
    }
    for (size_t j = digit_count; j < lane_count; j++) {
        ok &= digits[j] == 0;
    }
    check(ok, what, k);
    // top:words below 2m: the number less m, as one subtraction writes it,
    // is below m, which holds exactly when the number was below 2m.
    uint64_t words[WORDS_MAX + 1];
    rsa_ifma_model_to_words(words, digits, k);
    int top_fits = words[k] <= 1;
    rsa_mont64_reduce_once_with_top(words, words, words[k], mod);
    int below_m = 0;
    for (size_t i = k; i-- > 0;) {
        if (words[i] != mod->m[i]) {
            below_m = words[i] < mod->m[i];
            break;
        }
    }
    check(top_fits && below_m, what, k);
}

// The number in digits, less m once, as k words.
static void reduced_words(uint64_t *words, const uint64_t *digits, const rsa_mont64_modulus *mod) {
    rsa_ifma_model_to_words(words, digits, mod->words);
    rsa_mont64_reduce_once_with_top(words, words, words[mod->words], mod);
}

// rsa_vp1_cpu with the bit and with the probe's bit alone against
// rsa_vp1, and with the bit against the known answer where want is not
// NULL. With the bit rsa_vp1_cpu must call rsa_ifma_public kernel_calls
// times, 1 for a modulus the kernel takes and 0 for one it refuses, and
// without it never.
static void compare_vp1(const uint8_t *n, size_t n_len, const uint8_t *sig, const uint8_t *want,
                        unsigned long kernel_calls) {
    uint8_t kernel[CH_RSA_MODULUS_MAX];
    uint8_t without_bit[CH_RSA_MODULUS_MAX];
    uint8_t words[CH_RSA_MODULUS_MAX];
    memset(kernel, 0x55, sizeof kernel);
    memset(without_bit, 0x33, sizeof without_bit);
    memset(words, 0xaa, sizeof words);
    unsigned long calls = rsa_ifma_model_public_calls;
    rsa_ifma_model_vp1_cpu(IFMA_CPU, n, n_len, sig, kernel);
    check(rsa_ifma_model_public_calls - calls == kernel_calls,
          "rsa_vp1_cpu's calls of rsa_ifma_public under the bit", n_len / 8);
    calls = rsa_ifma_model_public_calls;
    rsa_ifma_model_vp1_cpu(CH_CPU_PROBED, n, n_len, sig, without_bit);
    check(rsa_ifma_model_public_calls == calls, "rsa_vp1_cpu calls rsa_ifma_public without the bit",
          n_len / 8);
    rsa_ifma_model_vp1(n, n_len, sig, words);
    check(memcmp(kernel, words, n_len) == 0, "rsa_vp1_cpu against rsa_vp1", n_len / 8);
    check(memcmp(without_bit, words, n_len) == 0, "rsa_vp1_cpu without the bit against rsa_vp1",
          n_len / 8);
    if (want != NULL) {
        check(memcmp(kernel, want, n_len) == 0, "rsa_vp1_cpu against the known power", n_len / 8);
    }
}

static void signatures_below_m(const uint8_t *n, size_t n_len) {
    uint8_t sig[CH_RSA_MODULUS_MAX];
    memset(sig, 0, n_len);
    compare_vp1(n, n_len, sig, sig, 1);
    sig[n_len - 1] = 1;
    compare_vp1(n, n_len, sig, sig, 1);
    memcpy(sig, n, n_len);
    sig[n_len - 1] -= 1; // n is odd
    compare_vp1(n, n_len, sig, sig, 1);
    for (int c = 0; c < 2; c++) {
        rng_fill(sig, n_len);
        sig[0] = (uint8_t)(sig[0] % n[0]); // below n's top byte, so below n
        compare_vp1(n, n_len, sig, NULL, 1);
    }
}

static void compare_public(const uint8_t *base, const rsa_mont64_modulus *mod,
                           const uint64_t *digit_r2) {
    size_t n_len = 8 * mod->words;
    uint8_t kernel[CH_RSA_MODULUS_MAX];
    uint8_t words[CH_RSA_MODULUS_MAX];
    memset(kernel, 0x55, sizeof kernel);
    memset(words, 0xaa, sizeof words);
    rsa_ifma_model_public(kernel, base, n_len, mod, digit_r2);
    rsa_mont64_public(words, base, n_len, mod);
    check(memcmp(kernel, words, n_len) == 0, "rsa_ifma_public against rsa_mont64_public",
          mod->words);
}

static void bases_at_or_above_m(const uint8_t *n, const rsa_mont64_modulus *mod,
                                const uint64_t *digit_r2) {
    size_t n_len = 8 * mod->words;
    uint8_t base[CH_RSA_MODULUS_MAX];
    compare_public(n, mod, digit_r2);
    for (int c = 0; c < 2; c++) {
        rng_fill(base, n_len);
        memset(base, 0xff, 8);
        compare_public(base, mod, digit_r2);
    }
    memset(base, 0xff, n_len);
    compare_public(base, mod, digit_r2);
}

// rsa_ifma_public's chain of products for one random base, with each
// product's digits checked, and its end against rsa_mont64_public's.
static void product_chain(const rsa_mont64_modulus *mod, const uint64_t *digit_r2) {
    size_t k = mod->words;
    uint8_t base[CH_RSA_MODULUS_MAX];
    uint64_t base_words[WORDS_MAX];
    uint64_t base_digits[RSA_IFMA_TEST_LANES];
    uint64_t power[RSA_IFMA_TEST_LANES];
    rng_fill(base, 8 * k);
    rsa_mont64_from_bytes(base_words, k, base, 8 * k);
    rsa_ifma_model_to_digits(base_digits, base_words, k, k);
    rsa_ifma_model_to_digits(power, digit_r2, k, k);
    rsa_ifma_model_product(power, base_digits, power, mod);
    check_product_digits("the first product's digits", power, mod);
    for (int i = 0; i < 16; i++) {
        rsa_ifma_model_product(power, power, power, mod);
        check_product_digits("a square's digits", power, mod);
    }
    rsa_ifma_model_product(power, base_digits, power, mod);
    check_product_digits("the last product's digits", power, mod);
    uint64_t kernel[WORDS_MAX + 1];
    uint8_t want[CH_RSA_MODULUS_MAX];
    uint64_t want_words[WORDS_MAX];
    reduced_words(kernel, power, mod);
    rsa_mont64_public(want, base, 8 * k, mod);
    rsa_mont64_from_bytes(want_words, k, want, 8 * k);
    check(memcmp(kernel, want_words, k * sizeof(uint64_t)) == 0, "the chain's last number", k);
}

// A random number below m when below_m, and that number plus m, which is
// below 2m, otherwise: k + 1 words.
static void operand(uint64_t *words, const rsa_mont64_modulus *mod, int below_m) {
    size_t k = mod->words;
    for (size_t i = 0; i < k; i++) {
        words[i] = rng_next();
    }
    words[k - 1] %= mod->m[k - 1];
    words[k] = 0;
    if (!below_m) {
        ct_u128 carry = 0;
        for (size_t i = 0; i < k; i++) {
            carry += (ct_u128)words[i] + mod->m[i];
            words[i] = (uint64_t)carry;
            carry >>= 64;
        }
        words[k] = (uint64_t)carry;
    }
}

// The product of two operands below 2m, each at or above m, against the
// product of the operands less m.
static void products_up_to_two_m(const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    for (int c = 0; c < 4; c++) {
        uint64_t a[WORDS_MAX + 1];
        uint64_t b[WORDS_MAX + 1];
        operand(a, mod, 0);
        operand(b, mod, c % 2);
        uint64_t a_digits[RSA_IFMA_TEST_LANES];
        uint64_t b_digits[RSA_IFMA_TEST_LANES];
        uint64_t product[RSA_IFMA_TEST_LANES];
        rsa_ifma_model_to_digits(a_digits, a, k + 1, k);
        rsa_ifma_model_to_digits(b_digits, b, k + 1, k);
        rsa_ifma_model_product(product, a_digits, b_digits, mod);
        check_product_digits("a product of operands up to 2m", product, mod);
        uint64_t wide[WORDS_MAX + 1];
        uint64_t reduced[WORDS_MAX + 1];
        reduced_words(wide, product, mod);
        rsa_mont64_reduce_once_with_top(a, a, a[k], mod);
        rsa_mont64_reduce_once_with_top(b, b, b[k], mod);
        rsa_ifma_model_to_digits(a_digits, a, k, k);
        rsa_ifma_model_to_digits(b_digits, b, k, k);
        rsa_ifma_model_product(product, a_digits, b_digits, mod);
        reduced_words(reduced, product, mod);
        check(memcmp(wide, reduced, k * sizeof(uint64_t)) == 0,
              "a product of operands up to 2m against the same product below m", k);
    }
}

static void run_modulus(const uint8_t *n, size_t k) {
    size_t n_len = 8 * k;
    rsa_mont64_modulus mod;
    uint64_t digit_r2[WORDS_MAX];
    rsa_mont64_modulus_init(&mod, n, n_len, 8 * n_len);
    power_of_two_by_doubling(digit_r2, &mod, 104 * rsa_ifma_digit_count(k));
    signatures_below_m(n, n_len);
    bases_at_or_above_m(n, &mod, digit_r2);
    product_chain(&mod, digit_r2);
    products_up_to_two_m(&mod);
}

// A modulus rsa_vp1_cpu must hand to rsa_vp1 under the bit, with a
// random signature whose top byte is below the modulus's.
static void compare_refused(const uint8_t *n, size_t n_len) {
    uint8_t sig[CH_RSA_MODULUS_MAX];
    rng_fill(sig, n_len);
    sig[0] = (uint8_t)(sig[0] % n[0]);
    compare_vp1(n, n_len, sig, NULL, 0);
}

static void run_refused_moduli(void) {
    uint8_t n[CH_RSA_MODULUS_MAX];
    rng_fill(n, 256);
    n[0] |= 0x80;
    n[255] &= 0xfe;
    compare_refused(n, 256); // even
    n[255] |= 1;
    n[0] = (uint8_t)((n[0] & 0x7f) | 0x40);
    compare_refused(n, 256); // top bit clear
    rng_fill(n, 248);
    n[0] |= 0x80;
    n[247] |= 1;
    compare_refused(n, 248); // 31 words
    rng_fill(n, 260);
    n[0] |= 0x80;
    n[259] |= 1;
    compare_refused(n, 260); // 260 bytes, so the top word is half full
}

// The number in count lanes at 52 bits apart, modulo 2^(52 * count), in
// words[0..67).
#define VALUE_WORDS 67
static void lanes_value(uint64_t *words, const uint64_t *lanes, size_t count) {
    memset(words, 0, VALUE_WORDS * sizeof(uint64_t));
    for (size_t j = 0; j < count; j++) {
        size_t bit = 52 * j;
        ct_u128 add = (ct_u128)lanes[j] << (bit % 64);
        for (size_t i = bit / 64; i < VALUE_WORDS && add != 0; i++) {
            add += words[i];
            words[i] = (uint64_t)add;
            add >>= 64;
        }
    }
    size_t bits = 52 * count;
    words[bits / 64] &= (UINT64_C(1) << (bits % 64)) - 1;
    for (size_t i = bits / 64 + 1; i < VALUE_WORDS; i++) {
        words[i] = 0;
    }
}

static void run_normalize(void) {
    for (int c = 0; c < NORMALIZE_CASES; c++) {
        size_t registers = 1 + (size_t)(rng_next() % RSA_IFMA_REGISTERS_MAX);
        size_t count = 8 * registers;
        uint64_t lanes[RSA_IFMA_TEST_LANES];
        extreme_lanes(lanes, count);
        uint64_t before[VALUE_WORDS];
        uint64_t after[VALUE_WORDS];
        lanes_value(before, lanes, count);
        rsa_ifma_model_normalize(lanes, registers);
        lanes_value(after, lanes, count);
        int ok = memcmp(before, after, sizeof before) == 0;
        for (size_t j = 0; j < count; j++) {
            ok &= lanes[j] <= DIGIT_MASK;
        }
        compared++;
        if (!ok) {
            failures++;
            (void)fprintf(stderr,
                          "FAIL normalize_digits changes the number or leaves a digit at 2^52 "
                          "or above, in %zu registers\n",
                          registers);
        }
    }
}

int main(void) {
    uint64_t seed = rng_seed_from_env();
    run_normalize();
    run_refused_moduli();
    for (size_t k = RSA_IFMA_WORDS_MIN; k <= WORDS_MAX; k++) {
        for (int kind = 0; kind < RSA_IFMA_MODULUS_KINDS; kind++) {
            uint8_t n[CH_RSA_MODULUS_MAX];
            if (modulus_of_kind(n, k, kind)) {
                run_modulus(n, k);
            }
        }
    }
    if (failures != 0) {
        (void)fprintf(stderr,
                      "rsa_ifma model: %d of %lu checks failed (seed 0x%016llx; rerun with "
                      "CH_RSA_EQUIV_SEED=0x%016llx)\n",
                      failures, compared, (unsigned long long)seed, (unsigned long long)seed);
        return 1;
    }
    (void)printf("rsa_ifma model: %lu checks pass from %d to %d words (seed 0x%016llx)\n", compared,
                 RSA_IFMA_WORDS_MIN, WORDS_MAX, (unsigned long long)seed);
    return 0;
}
