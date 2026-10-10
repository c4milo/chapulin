// Test code only: entries with external names into rsa_avx2.c's static
// functions, which test/rsa_avx2_test.h declares. A unit includes this
// file after rsa_avx2.c, with RSA_AVX2_ENTRY(name) defined to give each
// entry the unit's prefix: test/rsa_avx2_model.c over the lane model, and
// test/rsa_avx2_instructions.c on the instructions. Under the instructions
// the entries turn AVX2 on for themselves, as rsa_avx2.c's functions do,
// so that they can inline the kernel's functions.
#ifndef RSA_AVX2_ENTRY
#error "a unit defines RSA_AVX2_ENTRY before it includes test/rsa_avx2_entries.h"
#endif

_Static_assert(NUMBER_LANES <= RSA_AVX2_TEST_LANES,
               "test/rsa_avx2_test.h's arrays hold a number of rsa_avx2.c's layout");

#ifndef CH_RSA_AVX2_MODEL
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx2"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx2")
#endif
#endif

void RSA_AVX2_ENTRY(lane_operation)(int operation, const uint64_t *x, const uint64_t *y,
                                    uint64_t *out) {
    rsa_avx2_lanes first = lanes_load(x);
    rsa_avx2_lanes second = lanes_load(y);
    rsa_avx2_lanes result = lanes_zero();
    switch (operation) {
    case RSA_AVX2_TEST_ZERO:
        result = lanes_zero();
        break;
    case RSA_AVX2_TEST_BROADCAST:
        result = lanes_broadcast(y[0]);
        break;
    case RSA_AVX2_TEST_LOAD_STORE:
        result = first;
        break;
    case RSA_AVX2_TEST_MULTIPLY:
        result = lanes_multiply(first, second);
        break;
    case RSA_AVX2_TEST_ADD:
        result = lanes_add(first, second);
        break;
    case RSA_AVX2_TEST_FIRST_FROM:
        result = lanes_first_from(first, second);
        break;
    case RSA_AVX2_TEST_UPPER_TWO:
        result = lanes_upper_two(first, second);
        break;
    default:
        break;
    }
    lanes_store(out, result);
}

void RSA_AVX2_ENTRY(to_digits)(uint64_t *number, const uint64_t *words, size_t word_count,
                               size_t modulus_words) {
    words_to_digits(number, words, word_count, rsa_avx2_digit_count(modulus_words),
                    RSA_AVX2_DIGIT_BITS(modulus_words));
}

void RSA_AVX2_ENTRY(to_words)(uint64_t *words, const uint64_t *number, size_t modulus_words) {
    digits_to_words(words, modulus_words, number, rsa_avx2_digit_count(modulus_words),
                    RSA_AVX2_DIGIT_BITS(modulus_words));
}

void RSA_AVX2_ENTRY(multiply)(uint64_t *out, const uint64_t *a, const uint64_t *b,
                              const rsa_mont64_modulus *mod) {
    rsa_avx2_modulus modulus;
    modulus_from_words(&modulus, mod);
    multiply(out, a, b, &modulus);
}

void RSA_AVX2_ENTRY(square)(uint64_t *out, const uint64_t *a, const rsa_mont64_modulus *mod) {
    rsa_avx2_modulus modulus;
    modulus_from_words(&modulus, mod);
    square(out, a, &modulus);
}

#ifndef CH_RSA_AVX2_MODEL
#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif
#endif
