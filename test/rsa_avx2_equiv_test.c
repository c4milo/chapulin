// bin/rsa_avx2_equiv_test: rsa_avx2.c on the AVX2 instructions against
// the same file over the lane model (test/rsa_avx2_model.c), which
// bin/rsa_avx2_model_test holds to rsa_mont64.c on every machine. Together
// the two carry the instructions to rsa_mont64.c's answers.
//
// From the same inputs, the model and the instructions write:
//
//   - each lane operation of rsa_avx2_lanes.h, on lanes that mix random
//     words, words of 32 bits and less, and lanes equal to the other
//     operand's;
//   - the conversions between words and digits at every word count;
//   - at every word count from RSA_AVX2_WORDS_MIN to RSA_MONT64_WORDS_MAX,
//     under the moduli bin/rsa_avx2_model_test takes, products and squares
//     of operands below m and up to 2m, every lane of a number compared,
//     and rsa_avx2_public's bytes for bases below and above m.
//
// Under the same moduli rsa_vp1_cpu with CH_CPU_AVX2, which runs the
// instructions, must write rsa_vp1's bytes.
//
// On another architecture this binary says so and passes. On an x86-64 CPU
// without AVX2 it skips, unless CH_REQUIRE_X86_KERNELS is 1
// (test/x86_kernels_cpu.h). Every runner CI draws has AVX2, and so does
// QEMU's max model, which test/docker-aes-runtime-qemu.sh rsa-avx2 runs it
// under.
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
    (void)printf("SKIP rsa_avx2 equivalence: the AVX2 kernel is x86-64 only (rsa_avx2.h)\n");
    return 0;
}

#else

#include "cpu_cfg.h"
#include "rsa.h"
#include "rsa_avx2.h"
#include "rsa_avx2_test.h"
#include "rsa_ifma_inputs.h"
#include "rsa_mont64.h"

_Static_assert(RSA_MONT64_WORDS_MAX == 64,
               "bin/rsa_avx2_equiv_test builds at the 512-byte bound, where the kernel holds "
               "both digit widths");

#define WORDS_MAX RSA_MONT64_WORDS_MAX
#define LANE_CASES 4000
#define AVX2_CPU (CH_CPU_PROBED | CH_CPU_AVX2)

static int failures = 0;
static unsigned long compared = 0;

static void check(int ok, const char *what, size_t size) {
    compared++;
    if (!ok) {
        failures++;
        (void)fprintf(stderr, "FAIL %s, at %zu\n", what, size);
    }
}

static const char *const operation_names[RSA_AVX2_TEST_OPERATIONS] = {
    "lanes_zero",      "lanes_broadcast", "lanes_load and lanes_store",
    "lanes_multiply",  "lanes_add",       "lanes_first_from",
    "lanes_upper_two",
};

// A random word, one of 32 bits or less, or one with its high half alone.
static uint64_t lane_word(void) {
    switch (rng_next() % 4) {
    case 0:
        return rng_next() >> 32;
    case 1:
        return rng_next() >> (rng_next() % 64);
    case 2:
        return rng_next() << 32;
    default:
        return rng_next();
    }
}

// Each lane operation from the same lanes on both. y takes x's lane in
// about half its lanes, so the comparisons see equal lanes too.
static void compare_lane_operations(void) {
    for (int operation = 0; operation < RSA_AVX2_TEST_OPERATIONS; operation++) {
        for (int c = 0; c < LANE_CASES; c++) {
            uint64_t x[4];
            uint64_t y[4];
            for (int j = 0; j < 4; j++) {
                x[j] = lane_word();
                y[j] = (rng_next() & 1) ? x[j] : lane_word();
            }
            uint64_t model[4];
            uint64_t instructions[4];
            rsa_avx2_model_lane_operation(operation, x, y, model);
            rsa_avx2_instructions_lane_operation(operation, x, y, instructions);
            check(memcmp(model, instructions, sizeof model) == 0, operation_names[operation], 4);
        }
    }
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

// The conversions, a product and a square, of operands of each kind, below
// m and up to 2m.
static void compare_products(const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    for (int c = 0; c < 4; c++) {
        uint64_t a[WORDS_MAX + 1];
        uint64_t b[WORDS_MAX + 1];
        operand(a, mod, c & 1);
        operand(b, mod, c & 2);
        uint64_t a_digits[RSA_AVX2_TEST_LANES] = {0};
        uint64_t b_digits[RSA_AVX2_TEST_LANES] = {0};
        uint64_t instructions[RSA_AVX2_TEST_LANES] = {0};
        rsa_avx2_model_to_digits(a_digits, a, k + 1, k);
        rsa_avx2_instructions_to_digits(instructions, a, k + 1, k);
        check(memcmp(a_digits, instructions, sizeof a_digits) == 0, "words_to_digits", k);
        rsa_avx2_model_to_digits(b_digits, b, k + 1, k);
        uint64_t model[RSA_AVX2_TEST_LANES] = {0};
        rsa_avx2_model_multiply(model, a_digits, b_digits, mod);
        memset(instructions, 0, sizeof instructions);
        rsa_avx2_instructions_multiply(instructions, a_digits, b_digits, mod);
        check(memcmp(model, instructions, sizeof model) == 0, "the product", k);
        memset(model, 0, sizeof model);
        memset(instructions, 0, sizeof instructions);
        rsa_avx2_model_square(model, a_digits, mod);
        rsa_avx2_instructions_square(instructions, a_digits, mod);
        check(memcmp(model, instructions, sizeof model) == 0, "the square", k);
        uint64_t model_words[WORDS_MAX + 1];
        uint64_t instruction_words[WORDS_MAX + 1];
        rsa_avx2_model_to_words(model_words, model, k);
        rsa_avx2_instructions_to_words(instruction_words, model, k);
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
    rsa_avx2_model_public(model, base, n_len, mod, digit_r2);
    rsa_avx2_public(instructions, base, n_len, mod, digit_r2);
    check(memcmp(model, instructions, n_len) == 0, "rsa_avx2_public", mod->words);
}

// rsa_vp1_cpu with the bit, on the instructions, against rsa_vp1.
static void compare_vp1(const uint8_t *n, size_t n_len, const uint8_t *sig) {
    uint8_t kernel[CH_RSA_MODULUS_MAX];
    uint8_t words[CH_RSA_MODULUS_MAX];
    memset(kernel, 0x55, sizeof kernel);
    memset(words, 0xaa, sizeof words);
    rsa_vp1_cpu(AVX2_CPU, n, n_len, sig, kernel);
    rsa_vp1(n, n_len, sig, words);
    check(memcmp(kernel, words, n_len) == 0, "rsa_vp1_cpu against rsa_vp1", n_len / 8);
}

static void run_modulus(const uint8_t *n, size_t k) {
    size_t n_len = 8 * k;
    rsa_mont64_modulus mod;
    uint64_t digit_r2[WORDS_MAX];
    rsa_mont64_modulus_init(&mod, n, n_len, 8 * n_len);
    power_of_two_by_doubling(digit_r2, &mod, rsa_avx2_r2_exponent(k));
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
    if (!x86_cpu_has_avx2()) {
        if (x86_kernels_required()) {
            (void)fprintf(stderr, "rsa_avx2 equivalence: this CPU lacks AVX2, and "
                                  "CH_REQUIRE_X86_KERNELS is 1\n");
            return 1;
        }
        (void)printf("SKIP the AVX2 RSA kernel: this CPU lacks AVX2\n");
        return 0;
    }
    uint64_t seed = rng_seed_from_env();
    compare_lane_operations();
    for (size_t k = RSA_AVX2_WORDS_MIN; k <= WORDS_MAX; k++) {
        for (int kind = 0; kind < RSA_IFMA_MODULUS_KINDS; kind++) {
            uint8_t n[CH_RSA_MODULUS_MAX];
            if (modulus_of_kind(n, k, kind)) {
                run_modulus(n, k);
            }
        }
    }
    if (failures != 0) {
        (void)fprintf(stderr,
                      "rsa_avx2 equivalence: %d of %lu comparisons differ (seed 0x%016llx; "
                      "rerun with CH_RSA_EQUIV_SEED=0x%016llx)\n",
                      failures, compared, (unsigned long long)seed, (unsigned long long)seed);
        return 1;
    }
    (void)printf("rsa_avx2 equivalence: %lu comparisons agree between the instructions and the "
                 "model (seed 0x%016llx)\n",
                 compared, (unsigned long long)seed);
    return 0;
}

#endif // __x86_64__
