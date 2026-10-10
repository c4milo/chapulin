// Test code only: the calls bin/rsa_avx2_model_test and
// bin/rsa_avx2_equiv_test make into rsa_avx2.c's static functions, and the
// operation codes of the lane test.
//
// test/rsa_avx2_model.c compiles rsa_mont.c and rsa_avx2.c over the lane
// model, test/rsa_avx2_model_lanes.h, and gives their calls the prefix
// rsa_avx2_model_. test/rsa_avx2_instructions.c compiles rsa_avx2.c on the
// instructions, x86-64 alone, and gives its static functions the prefix
// rsa_avx2_instructions_; its rsa_avx2_public keeps the name rsa_mont.c
// calls. Each unit then includes test/rsa_avx2_entries.h, which defines
// the entries below under its prefix.
#ifndef CH_TEST_RSA_AVX2_TEST_H
#define CH_TEST_RSA_AVX2_TEST_H

#include <stddef.h>
#include <stdint.h>

#include "rsa_mont64.h"

// The most lanes a number takes: four zero lanes below its digits and 40
// registers of four, at the 512-byte bound. bin/rsa_avx2_model_test_384,
// at the 384-byte bound, uses the first 120.
#define RSA_AVX2_TEST_LANES 160

// One code for each operation of rsa_avx2_lanes.h. The lane test runs each
// on the model and on the instructions from the same lanes and compares
// what they write.
enum rsa_avx2_test_operation {
    RSA_AVX2_TEST_ZERO,
    RSA_AVX2_TEST_BROADCAST,
    RSA_AVX2_TEST_LOAD_STORE,
    RSA_AVX2_TEST_MULTIPLY,
    RSA_AVX2_TEST_ADD,
    RSA_AVX2_TEST_FIRST_FROM,
    RSA_AVX2_TEST_UPPER_TWO,
    RSA_AVX2_TEST_OPERATIONS
};

// The entries, under the model's prefix:
//
//   - lane_operation runs one operation on the lanes x and y, four words
//     each, and writes the result's lanes to out. BROADCAST takes lane 0 of
//     y as its value;
//   - to_digits writes the number in words[0..word_count) as a number of
//     rsa_avx2.c's layout for a modulus of modulus_words words: four zero
//     lanes, its digits, and zeros up to RSA_AVX2_TEST_LANES at the
//     512-byte bound or 120 at the 384-byte one;
//   - to_words writes modulus_words + 1 words from such a number;
//   - multiply and square run the product under the record of mod's
//     modulus, the second with a as both operands;
//   - public, vp1 and vp1_cpu are rsa_avx2_public, rsa_vp1 and rsa_vp1_cpu,
//     compiled with the model. public adds 1 to public_calls and then runs
//     kernel_public, which is rsa_avx2_public's own text, and vp1_cpu
//     calls public, so public_calls counts the calls of vp1_cpu that ran
//     the kernel beside the calls of public itself.
void rsa_avx2_model_lane_operation(int operation, const uint64_t *x, const uint64_t *y,
                                   uint64_t *out);
void rsa_avx2_model_to_digits(uint64_t *number, const uint64_t *words, size_t word_count,
                              size_t modulus_words);
void rsa_avx2_model_to_words(uint64_t *words, const uint64_t *number, size_t modulus_words);
void rsa_avx2_model_multiply(uint64_t *out, const uint64_t *a, const uint64_t *b,
                             const rsa_mont64_modulus *mod);
void rsa_avx2_model_square(uint64_t *out, const uint64_t *a, const rsa_mont64_modulus *mod);
void rsa_avx2_model_public(uint8_t *out, const uint8_t *base, size_t len,
                           const rsa_mont64_modulus *mod, const uint64_t *digit_r2);
void rsa_avx2_model_kernel_public(uint8_t *out, const uint8_t *base, size_t len,
                                  const rsa_mont64_modulus *mod, const uint64_t *digit_r2);
extern unsigned long rsa_avx2_model_public_calls;
void rsa_avx2_model_vp1(const uint8_t *n, size_t n_len, const uint8_t *sig, uint8_t *em);
void rsa_avx2_model_vp1_cpu(uint32_t cpu, const uint8_t *n, size_t n_len, const uint8_t *sig,
                            uint8_t *em);

// The same entries on the instructions, which an x86-64 CPU with AVX2
// runs. rsa_avx2_public, rsa_vp1 and rsa_vp1_cpu keep their own names there
// (rsa_avx2.h, rsa.h).
#ifdef __x86_64__
void rsa_avx2_instructions_lane_operation(int operation, const uint64_t *x, const uint64_t *y,
                                          uint64_t *out);
void rsa_avx2_instructions_to_digits(uint64_t *number, const uint64_t *words, size_t word_count,
                                     size_t modulus_words);
void rsa_avx2_instructions_to_words(uint64_t *words, const uint64_t *number, size_t modulus_words);
void rsa_avx2_instructions_multiply(uint64_t *out, const uint64_t *a, const uint64_t *b,
                                    const rsa_mont64_modulus *mod);
void rsa_avx2_instructions_square(uint64_t *out, const uint64_t *a, const rsa_mont64_modulus *mod);
#endif

#endif
