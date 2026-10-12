// Proves, over every input, that four steps sha512_compress_blocks.c writes
// otherwise than FIPS 180-4 does compute what the standard's own form
// computes (proof/sha512_compress_blocks_steps.h):
//
//   the four sigma functions, written as nested rotates, against equations
//   4.10 to 4.13;
//   choice and majority, in three operations each, against equations 4.8
//   and 4.9;
//   next_word, on a ring of sixteen words at each of its sixteen indices,
//   against §6.4.2 step 1 on the same sixteen words in order;
//   eight_rounds, whose calls rename the working variables, against eight
//   rounds of §6.4.2 step 3 that move them, from any eight variables, any
//   eight words and any eight constants.
//
// sha512_compress_blocks_advancing_harness.c proves a fifth step,
// eight_rounds_advancing, in a formula of its own. The file's function is
// made of those five steps and of three things no harness proves a value
// of: the load of a block's words (load_word and load_block), the sum that
// ends a block with the b ^ c it leaves for the next (end_block), and the
// order of the calls. bin/sha2_equiv_test and the published vectors hold
// those three. The whole function against sha512_compress in one formula
// returned no verdict in nine minutes (docs/verification.md), which is why
// the proof is of steps.
#include "harness.h"

#include "sha512_compress_blocks.c"

#include "sha512_compress_blocks_steps.h"

static void prove_forms(void) {
    uint64_t x = nondet_u64();
    uint64_t y = nondet_u64();
    uint64_t z = nondet_u64();
    __CPROVER_assert(upper_sigma0(x) ==
                         (standard_rotate(x, 28) ^ standard_rotate(x, 34) ^ standard_rotate(x, 39)),
                     "upper_sigma0 is equation 4.10");
    __CPROVER_assert(upper_sigma1(x) ==
                         (standard_rotate(x, 14) ^ standard_rotate(x, 18) ^ standard_rotate(x, 41)),
                     "upper_sigma1 is equation 4.11");
    __CPROVER_assert(lower_sigma0(x) == (standard_rotate(x, 1) ^ standard_rotate(x, 8) ^ (x >> 7)),
                     "lower_sigma0 is equation 4.12");
    __CPROVER_assert(lower_sigma1(x) ==
                         (standard_rotate(x, 19) ^ standard_rotate(x, 61) ^ (x >> 6)),
                     "lower_sigma1 is equation 4.13");
    __CPROVER_assert(choice(x, y, z) == ((x & y) ^ (~x & z)), "choice is equation 4.8");
    __CPROVER_assert(majority(y, x ^ y, y ^ z) == ((x & y) ^ (x & z) ^ (y & z)),
                     "majority is equation 4.9");
}

static void prove_next_word(void) {
    uint64_t ring[16];
    for (size_t j = 0; j < 16; j++) {
        ring[j] = nondet_u64();
    }
    size_t i = nondet_size_t();
    __CPROVER_assume(i < 16);
    uint64_t expected = standard_word(ring, i);
    uint64_t word = next_word(ring, i);
    __CPROVER_assert(word == expected, "next_word returns W[t]");
    __CPROVER_assert(ring[i] == expected, "next_word writes W[t] over W[t - 16]");
}

static void prove_eight_rounds(void) {
    uint64_t expected[8];
    uint64_t constants[8];
    uint64_t words[8];
    for (size_t j = 0; j < 8; j++) {
        expected[j] = nondet_u64();
        constants[j] = nondet_u64();
        words[j] = nondet_u64();
    }
    working_variables v = variables_of(expected);
    for (size_t j = 0; j < 8; j++) {
        standard_round(expected, constants[j] + words[j]);
    }
    eight_rounds(&v, constants, words);
    __CPROVER_assert(v.a == expected[0] && v.b == expected[1] && v.c == expected[2] &&
                         v.d == expected[3],
                     "eight_rounds leaves a to d as eight rounds of the standard do");
    __CPROVER_assert(v.e == expected[4] && v.f == expected[5] && v.g == expected[6] &&
                         v.h == expected[7],
                     "eight_rounds leaves e to h as eight rounds of the standard do");
    __CPROVER_assert(v.b_xor_c == (expected[1] ^ expected[2]),
                     "eight_rounds leaves b ^ c for the round after");
}

int main(void) {
    prove_forms();
    prove_next_word();
    prove_eight_rounds();
    return 0;
}
