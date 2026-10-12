// Proves, over every input, that sha512_compress_blocks.c's
// eight_rounds_advancing computes what FIPS 180-4 §6.4.2 computes
// (proof/sha512_compress_blocks_steps.h): from any eight working variables,
// any ring of sixteen schedule words and any eight constants, at each of
// the two indices the file calls it with, 0 and 8, it leaves the working
// variables and the ring that the standard's eight steps leave, each step
// the next schedule word written over the word sixteen before it and then
// the round that takes it.
//
// It is a formula of its own because it is most of the cost:
// sha512_compress_blocks_steps_harness.c proves the other four steps in
// seconds.
#include "harness.h"

#include "sha512_compress_blocks.c"

#include "sha512_compress_blocks_steps.h"

int main(void) {
    uint64_t expected[8];
    uint64_t constants[8];
    uint64_t expected_ring[16];
    uint64_t ring[16];
    for (size_t j = 0; j < 8; j++) {
        expected[j] = nondet_u64();
        constants[j] = nondet_u64();
    }
    for (size_t j = 0; j < 16; j++) {
        expected_ring[j] = nondet_u64();
        ring[j] = expected_ring[j];
    }
    size_t i = nondet_size_t();
    __CPROVER_assume(i == 0 || i == 8);
    working_variables v = variables_of(expected);
    for (size_t j = 0; j < 8; j++) {
        expected_ring[i + j] = standard_word(expected_ring, i + j);
        standard_round(expected, constants[j] + expected_ring[i + j]);
    }
    eight_rounds_advancing(&v, constants, ring, i);
    __CPROVER_assert(v.a == expected[0] && v.b == expected[1] && v.c == expected[2] &&
                         v.d == expected[3],
                     "eight_rounds_advancing leaves a to d as the standard's eight rounds do");
    __CPROVER_assert(v.e == expected[4] && v.f == expected[5] && v.g == expected[6] &&
                         v.h == expected[7],
                     "eight_rounds_advancing leaves e to h as the standard's eight rounds do");
    __CPROVER_assert(v.b_xor_c == (expected[1] ^ expected[2]),
                     "eight_rounds_advancing leaves b ^ c for the round after");
    for (size_t j = 0; j < 16; j++) {
        __CPROVER_assert(ring[j] == expected_ring[j],
                         "eight_rounds_advancing leaves the ring the standard's eight words");
    }
    return 0;
}
