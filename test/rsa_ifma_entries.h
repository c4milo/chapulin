// Test code only: entries with external names into rsa_ifma.c's static
// functions, which test/rsa_ifma_test.h declares. A unit includes this
// file after rsa_ifma.c, with RSA_IFMA_ENTRY(name) defined to give each
// entry the unit's prefix: test/rsa_ifma_model.c over the lane model, and
// test/rsa_ifma_instructions.c on the instructions. Under the
// instructions the entries turn AVX-512F and AVX-512 IFMA on for
// themselves, as rsa_ifma.c's functions do, so that they can inline the
// kernel's functions.
#ifndef RSA_IFMA_ENTRY
#error "a unit defines RSA_IFMA_ENTRY before it includes test/rsa_ifma_entries.h"
#endif

#ifndef CH_RSA_IFMA_MODEL
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx512f,avx512ifma"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx512f,avx512ifma")
#endif
#endif

void RSA_IFMA_ENTRY(lane_operation)(int operation, const uint64_t *x, const uint64_t *y,
                                    const uint64_t *z, unsigned bits, uint64_t *out,
                                    unsigned *bits_out) {
    rsa_ifma_lanes first = lanes_load(x);
    rsa_ifma_lanes second = lanes_load(y);
    rsa_ifma_lanes third = lanes_load(z);
    rsa_ifma_lanes result = lanes_zero();
    unsigned result_bits = 0;
    switch (operation) {
    case RSA_IFMA_TEST_ZERO:
        result = lanes_zero();
        break;
    case RSA_IFMA_TEST_BROADCAST:
        result = lanes_broadcast(y[0]);
        break;
    case RSA_IFMA_TEST_LOAD_STORE:
        result = first;
        break;
    case RSA_IFMA_TEST_MULTIPLY_ADD_LOW:
        result = lanes_multiply_add_low(first, second, third);
        break;
    case RSA_IFMA_TEST_MULTIPLY_ADD_HIGH:
        result = lanes_multiply_add_high(first, second, third);
        break;
    case RSA_IFMA_TEST_DOWN_ONE:
        result = lanes_down_one(first, second);
        break;
    case RSA_IFMA_TEST_UP_ONE:
        result = lanes_up_one(first, second);
        break;
    case RSA_IFMA_TEST_FIRST:
        result = lanes_broadcast(lanes_first(first));
        break;
    case RSA_IFMA_TEST_REPLACE_FIRST:
        result = lanes_replace_first(first, y[0]);
        break;
    case RSA_IFMA_TEST_SHIFT_RIGHT_52:
        result = lanes_shift_right_52(first);
        break;
    case RSA_IFMA_TEST_AND:
        result = lanes_and(first, second);
        break;
    case RSA_IFMA_TEST_ADD:
        result = lanes_add(first, second);
        break;
    case RSA_IFMA_TEST_ABOVE:
        result_bits = lanes_above(first, second);
        break;
    case RSA_IFMA_TEST_EQUAL:
        result_bits = lanes_equal(first, second);
        break;
    case RSA_IFMA_TEST_ADD_WHERE:
        result = lanes_add_where(first, (rsa_ifma_lane_bits)bits, second, third);
        break;
    default:
        break;
    }
    lanes_store(out, result);
    *bits_out = result_bits;
}

void RSA_IFMA_ENTRY(normalize)(uint64_t *lanes, size_t registers) {
    rsa_ifma_lanes sum[RSA_IFMA_REGISTERS_MAX];
    for (size_t i = 0; i < registers; i++) {
        sum[i] = lanes_load(lanes + DIGITS_PER_REGISTER * i);
    }
    normalize_digits(sum, registers);
    for (size_t i = 0; i < registers; i++) {
        lanes_store(lanes + DIGITS_PER_REGISTER * i, sum[i]);
    }
}

void RSA_IFMA_ENTRY(to_digits)(uint64_t *digits, const uint64_t *words, size_t word_count,
                               size_t modulus_words) {
    size_t digit_count = rsa_ifma_digit_count(modulus_words);
    size_t registers = (digit_count + DIGITS_PER_REGISTER - 1) / DIGITS_PER_REGISTER;
    words_to_digits(digits, words, word_count, digit_count, DIGITS_PER_REGISTER * registers);
}

void RSA_IFMA_ENTRY(to_words)(uint64_t *words, const uint64_t *digits, size_t modulus_words) {
    digits_to_words(words, modulus_words, digits, rsa_ifma_digit_count(modulus_words));
}

void RSA_IFMA_ENTRY(product)(uint64_t *out, const uint64_t *a, const uint64_t *b,
                             const rsa_mont64_modulus *mod) {
    rsa_ifma_modulus modulus;
    modulus_from_words(&modulus, mod);
    almost_montgomery_product(out, a, b, &modulus);
}

#ifndef CH_RSA_IFMA_MODEL
#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif
#endif
