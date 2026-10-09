// bin/rsa_ifma_equiv_test: rsa_ifma.c on the AVX-512 IFMA instructions
// against the same file over the lane model (test/rsa_ifma_model.c), which
// bin/rsa_ifma_model_test holds to rsa_mont64.c on every machine. Together
// the two carry the instructions to rsa_mont64.c's answers.
//
// From the same inputs, the model and the instructions write:
//
//   - each lane operation of rsa_ifma_lanes.h, on lanes that mix random
//     words, lanes at and around 2^52 and lanes equal to the other
//     operand's, under random mask bits;
//   - normalize_digits on lanes chosen for its carries, at every register
//     count up to ten;
//   - the conversions between words and digits at every word count;
//   - at every word count from RSA_IFMA_WORDS_MIN to RSA_MONT64_WORDS_MAX,
//     under the moduli bin/rsa_ifma_model_test takes, products of
//     operands below m and up to 2m, every lane of the kernel's registers
//     compared, and rsa_ifma_public's bytes for bases below and above m.
//
// Under the same moduli rsa_vp1_cpu with CH_CPU_AVX512_IFMA, which runs
// the instructions, must write rsa_vp1's bytes.
//
// On another architecture this binary says so and passes. On an x86-64 CPU
// without AVX-512 IFMA it skips, unless CH_REQUIRE_AVX512_IFMA is 1
// (test/x86_kernels_cpu.h): Intel's emulator, SDE, runs it under that
// variable in the nightly.
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#include "ch_assert.h"
#include "x86_kernels_cpu.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#ifndef __x86_64__

int main(void) {
    (void)printf("SKIP rsa_ifma equivalence: the AVX-512 IFMA kernel is x86-64 only "
                 "(rsa_ifma.h)\n");
    return 0;
}

#else

#include "cpu_cfg.h"
#include "rsa.h"
#include "rsa_ifma.h"
#include "rsa_ifma_inputs.h"
#include "rsa_ifma_test.h"
#include "rsa_mont64.h"

_Static_assert(
    RSA_MONT64_WORDS_MAX == 64,
    "bin/rsa_ifma_equiv_test builds at the 512-byte bound, the most registers the kernel takes");

#define WORDS_MAX RSA_MONT64_WORDS_MAX
#define LANE_CASES 2000
#define NORMALIZE_CASES 5000
#define IFMA_CPU (CH_CPU_PROBED | CH_CPU_AVX512_IFMA)

static int failures = 0;
static unsigned long compared = 0;

static void check(int ok, const char *what, size_t size) {
    compared++;
    if (!ok) {
        failures++;
        (void)fprintf(stderr, "FAIL %s, at %zu\n", what, size);
    }
}

static const char *const operation_names[RSA_IFMA_TEST_OPERATIONS] = {
    "lanes_zero",
    "lanes_broadcast",
    "lanes_load and lanes_store",
    "lanes_multiply_add_low",
    "lanes_multiply_add_high",
    "lanes_down_one",
    "lanes_up_one",
    "lanes_first",
    "lanes_replace_first",
    "lanes_shift_right_52",
    "lanes_and",
    "lanes_add",
    "lanes_above",
    "lanes_equal",
    "lanes_add_where",
};

// Each lane operation from the same lanes on both. y takes x's lane in
// about half its lanes, so the comparisons see equal lanes too.
static void compare_lane_operations(void) {
    for (int operation = 0; operation < RSA_IFMA_TEST_OPERATIONS; operation++) {
        for (int c = 0; c < LANE_CASES; c++) {
            uint64_t x[8];
            uint64_t y[8];
            uint64_t z[8];
            extreme_lanes(x, 8);
            extreme_lanes(y, 8);
            extreme_lanes(z, 8);
            for (int j = 0; j < 8; j++) {
                y[j] = (rng_next() & 1) ? x[j] : y[j];
            }
            unsigned bits = (unsigned)(rng_next() & 0xff);
            uint64_t model[8];
            uint64_t instructions[8];
            unsigned model_bits = 0;
            unsigned instruction_bits = 0;
            rsa_ifma_model_lane_operation(operation, x, y, z, bits, model, &model_bits);
            rsa_ifma_instructions_lane_operation(operation, x, y, z, bits, instructions,
                                                 &instruction_bits);
            check(memcmp(model, instructions, sizeof model) == 0 && model_bits == instruction_bits,
                  operation_names[operation], 8);
        }
    }
}

static void compare_normalize(void) {
    for (int c = 0; c < NORMALIZE_CASES; c++) {
        size_t registers = 1 + (size_t)(rng_next() % 10);
        uint64_t model[RSA_IFMA_TEST_LANES];
        uint64_t instructions[RSA_IFMA_TEST_LANES];
        extreme_lanes(model, 8 * registers);
        memcpy(instructions, model, sizeof model);
        rsa_ifma_model_normalize(model, registers);
        rsa_ifma_instructions_normalize(instructions, registers);
        check(memcmp(model, instructions, 8 * registers * sizeof(uint64_t)) == 0,
              "normalize_digits, lanes", 8 * registers);
    }
}

static int same_lanes(const uint64_t *model, const uint64_t *instructions, size_t k) {
    size_t lane_count = 8 * ((rsa_ifma_digit_count(k) + 7) / 8);
    return memcmp(model, instructions, lane_count * sizeof(uint64_t)) == 0;
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

// The conversions and a product of operands of each kind, below m and up
// to 2m.
static void compare_products(const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    for (int c = 0; c < 4; c++) {
        uint64_t a[WORDS_MAX + 1];
        uint64_t b[WORDS_MAX + 1];
        operand(a, mod, c & 1);
        operand(b, mod, c & 2);
        uint64_t a_digits[RSA_IFMA_TEST_LANES];
        uint64_t b_digits[RSA_IFMA_TEST_LANES];
        uint64_t instructions[RSA_IFMA_TEST_LANES];
        rsa_ifma_model_to_digits(a_digits, a, k + 1, k);
        rsa_ifma_instructions_to_digits(instructions, a, k + 1, k);
        check(same_lanes(a_digits, instructions, k), "words_to_digits", k);
        rsa_ifma_model_to_digits(b_digits, b, k + 1, k);
        uint64_t model[RSA_IFMA_TEST_LANES];
        rsa_ifma_model_product(model, a_digits, b_digits, mod);
        rsa_ifma_instructions_product(instructions, a_digits, b_digits, mod);
        check(same_lanes(model, instructions, k), "almost_montgomery_product", k);
        uint64_t model_words[WORDS_MAX + 1];
        uint64_t instruction_words[WORDS_MAX + 1];
        rsa_ifma_model_to_words(model_words, model, k);
        rsa_ifma_instructions_to_words(instruction_words, model, k);
        check(memcmp(model_words, instruction_words, (k + 1) * sizeof(uint64_t)) == 0,
              "digits_to_words", k);
    }
}

static void compare_public(const uint8_t *base, const rsa_mont64_modulus *mod,
                           const uint64_t *digit_r2) {
    size_t n_len = 8 * mod->words;
    uint8_t model[CH_RSA_MODULUS_MAX];
    uint8_t instructions[CH_RSA_MODULUS_MAX];
    memset(model, 0x55, sizeof model);
    memset(instructions, 0xaa, sizeof instructions);
    rsa_ifma_model_public(model, base, n_len, mod, digit_r2);
    rsa_ifma_public(instructions, base, n_len, mod, digit_r2);
    check(memcmp(model, instructions, n_len) == 0, "rsa_ifma_public", mod->words);
}

// rsa_vp1_cpu with the bit, on the instructions, against rsa_vp1.
static void compare_vp1(const uint8_t *n, size_t n_len, const uint8_t *sig) {
    uint8_t kernel[CH_RSA_MODULUS_MAX];
    uint8_t words[CH_RSA_MODULUS_MAX];
    memset(kernel, 0x55, sizeof kernel);
    memset(words, 0xaa, sizeof words);
    rsa_vp1_cpu(IFMA_CPU, n, n_len, sig, kernel);
    rsa_vp1(n, n_len, sig, words);
    check(memcmp(kernel, words, n_len) == 0, "rsa_vp1_cpu against rsa_vp1", n_len / 8);
}

static void run_modulus(const uint8_t *n, size_t k) {
    size_t n_len = 8 * k;
    rsa_mont64_modulus mod;
    uint64_t digit_r2[WORDS_MAX];
    rsa_mont64_modulus_init(&mod, n, n_len, 8 * n_len);
    power_of_two_by_doubling(digit_r2, &mod, 104 * rsa_ifma_digit_count(k));
    compare_products(&mod);
    uint8_t base[CH_RSA_MODULUS_MAX];
    compare_public(n, &mod, digit_r2);
    memset(base, 0xff, n_len);
    compare_public(base, &mod, digit_r2);
    rng_fill(base, n_len);
    compare_public(base, &mod, digit_r2);
    base[0] = (uint8_t)(base[0] % n[0]); // below n's top byte, so below n
    compare_vp1(n, n_len, base);
    memcpy(base, n, n_len);
    base[n_len - 1] -= 1; // n is odd
    compare_vp1(n, n_len, base);
}

int main(void) {
    if (!x86_cpu_has_avx512_ifma()) {
        if (x86_ifma_required()) {
            (void)fprintf(stderr, "rsa_ifma equivalence: this CPU lacks AVX-512 IFMA, and "
                                  "CH_REQUIRE_AVX512_IFMA is 1\n");
            return 1;
        }
        (void)printf("SKIP the IFMA kernel: this CPU lacks AVX-512 IFMA\n");
        return 0;
    }
    uint64_t seed = rng_seed_from_env();
    compare_lane_operations();
    compare_normalize();
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
                      "rsa_ifma equivalence: %d of %lu comparisons differ (seed 0x%016llx; "
                      "rerun with CH_RSA_EQUIV_SEED=0x%016llx)\n",
                      failures, compared, (unsigned long long)seed, (unsigned long long)seed);
        return 1;
    }
    (void)printf("rsa_ifma equivalence: %lu comparisons agree between the instructions and the "
                 "model (seed 0x%016llx)\n",
                 compared, (unsigned long long)seed);
    return 0;
}

#endif // __x86_64__
