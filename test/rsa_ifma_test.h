// Test code only: the calls bin/rsa_ifma_model_test and
// bin/rsa_ifma_equiv_test make into rsa_ifma.c's static functions, and
// the operation codes of the lane test.
//
// test/rsa_ifma_model.c compiles rsa_mont.c and rsa_ifma.c over the lane
// model, test/rsa_ifma_model_lanes.h, and gives their calls the prefix
// rsa_ifma_model_. test/rsa_ifma_instructions.c compiles rsa_ifma.c on
// the instructions, x86-64 alone, and gives its static functions the
// prefix rsa_ifma_instructions_; its rsa_ifma_public keeps the name
// rsa_mont.c calls. Each unit then includes test/rsa_ifma_entries.h,
// which defines the entries below under its prefix.
#ifndef CH_TEST_RSA_IFMA_TEST_H
#define CH_TEST_RSA_IFMA_TEST_H

#include <stddef.h>
#include <stdint.h>

#include "rsa_mont64.h"

// The most lanes a number takes: ten registers of eight, at the 512-byte
// bound. bin/rsa_ifma_model_test_384, at the 384-byte bound, uses the
// first 64.
#define RSA_IFMA_TEST_LANES 80

// One code for each operation of rsa_ifma_lanes.h. The lane test runs each
// on the model and on the instructions from the same lanes and compares
// what they write.
enum rsa_ifma_test_operation {
    RSA_IFMA_TEST_ZERO,
    RSA_IFMA_TEST_BROADCAST,
    RSA_IFMA_TEST_LOAD_STORE,
    RSA_IFMA_TEST_MULTIPLY_ADD_LOW,
    RSA_IFMA_TEST_MULTIPLY_ADD_HIGH,
    RSA_IFMA_TEST_DOWN_ONE,
    RSA_IFMA_TEST_UP_ONE,
    RSA_IFMA_TEST_FIRST,
    RSA_IFMA_TEST_REPLACE_FIRST,
    RSA_IFMA_TEST_SHIFT_RIGHT_52,
    RSA_IFMA_TEST_AND,
    RSA_IFMA_TEST_ADD,
    RSA_IFMA_TEST_ABOVE,
    RSA_IFMA_TEST_EQUAL,
    RSA_IFMA_TEST_ADD_WHERE,
    RSA_IFMA_TEST_OPERATIONS
};

// The entries, under the model's prefix:
//
//   - lane_operation runs one operation on the lanes x, y and z, eight
//     words each, and the eight mask bits in bits. It writes the result's
//     lanes to out, or 0 in each for an operation that writes a mask, and
//     the mask, or 0, to *bits_out. FIRST writes lane 0 of x to every lane
//     of out, and BROADCAST and REPLACE_FIRST take lane 0 of y as their
//     value;
//   - normalize runs normalize_digits on lanes[0..8 * registers);
//   - to_digits writes the number in words[0..word_count) as the digits of
//     a modulus of modulus_words words, then zeros up to its register
//     count's lanes;
//   - to_words writes modulus_words + 1 words from those digits;
//   - product runs almost_montgomery_product under the record of mod's
//     modulus;
//   - public, vp1 and vp1_cpu are rsa_ifma_public, rsa_vp1 and rsa_vp1_cpu,
//     compiled with the model. public adds 1 to public_calls and then runs
//     kernel_public, which is rsa_ifma_public's own text, and vp1_cpu
//     calls public, so public_calls counts the calls of vp1_cpu that ran
//     the kernel beside the calls of public itself;
//   - power_of_two_mod is rsa_mont.c's, which test/rsa_ifma_model.c alone
//     compiles, so it has this prefix only.
void rsa_ifma_model_lane_operation(int operation, const uint64_t *x, const uint64_t *y,
                                   const uint64_t *z, unsigned bits, uint64_t *out,
                                   unsigned *bits_out);
void rsa_ifma_model_normalize(uint64_t *lanes, size_t registers);
void rsa_ifma_model_to_digits(uint64_t *digits, const uint64_t *words, size_t word_count,
                              size_t modulus_words);
void rsa_ifma_model_to_words(uint64_t *words, const uint64_t *digits, size_t modulus_words);
void rsa_ifma_model_product(uint64_t *out, const uint64_t *a, const uint64_t *b,
                            const rsa_mont64_modulus *mod);
void rsa_ifma_model_public(uint8_t *out, const uint8_t *base, size_t len,
                           const rsa_mont64_modulus *mod, const uint64_t *digit_r2);
void rsa_ifma_model_kernel_public(uint8_t *out, const uint8_t *base, size_t len,
                                  const rsa_mont64_modulus *mod, const uint64_t *digit_r2);
extern unsigned long rsa_ifma_model_public_calls;
void rsa_ifma_model_vp1(const uint8_t *n, size_t n_len, const uint8_t *sig, uint8_t *em);
void rsa_ifma_model_vp1_cpu(uint32_t cpu, const uint8_t *n, size_t n_len, const uint8_t *sig,
                            uint8_t *em);
void rsa_ifma_model_power_of_two_mod(uint64_t *rem, const uint64_t *m, size_t k, size_t exponent);

// The same entries on the instructions, which an x86-64 CPU with AVX-512
// IFMA runs. rsa_ifma_public, rsa_vp1 and rsa_vp1_cpu keep their own
// names there (rsa_ifma.h, rsa.h).
#ifdef __x86_64__
void rsa_ifma_instructions_lane_operation(int operation, const uint64_t *x, const uint64_t *y,
                                          const uint64_t *z, unsigned bits, uint64_t *out,
                                          unsigned *bits_out);
void rsa_ifma_instructions_normalize(uint64_t *lanes, size_t registers);
void rsa_ifma_instructions_to_digits(uint64_t *digits, const uint64_t *words, size_t word_count,
                                     size_t modulus_words);
void rsa_ifma_instructions_to_words(uint64_t *words, const uint64_t *digits, size_t modulus_words);
void rsa_ifma_instructions_product(uint64_t *out, const uint64_t *a, const uint64_t *b,
                                   const rsa_mont64_modulus *mod);
#endif

#endif
