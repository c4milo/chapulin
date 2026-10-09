// Proves: power_of_two_mod writes 2^exponent mod m at two words, for any
// odd m whose top bit is set and every exponent from 64 to 131, on the real
// 64x64->128 multiply and the real division. The reference is a doubling:
// 2^exponent mod m from 1, one bit at a time, each doubling followed by one
// subtraction of m where the 129-bit value is at or above it.
//
// Those exponents run the function's two shapes. From 64 to 127 it runs no
// step: rem is its start value, 2^exponent itself, which is below m. From
// 128 to 131 it runs one step of times_word_mod from a start bit of 0 to 3
// in the top word, whose quotient estimate is below 16. That step runs the
// estimate, the subtraction of the estimate times m and the passes that
// add m back: where m's top word is 2^63, the estimate passes the quotient
// and a pass runs.
//
// The bound is where the formula converges. A step's estimate is a 64-bit
// division of the top words, and the product of the estimate and m against
// the doubling is the multiplier equivalence docs/proofs.md calls the
// classic hard instance. Measured under this line's flags with kissat on
// an M1 Pro: exponents 64 to 131 in 39 s; 64 to 135, start bits to 7, no
// verdict in 600 s; 160 alone, start bit 32, none in 600 s; 64 to 191,
// every start bit, none in 1200 s. A step from any remainder below m, which
// the second step of every exponent from 192 up takes, is that harder case.
//
// What it does not prove: the value of a step whose estimate is wide, which
// every call rsa_vp1_cpu makes runs from its second step on, and the start
// bits 32 and 24 RSA-3072 and RSA-4096 take. bin/rsa_ifma_model_test holds
// rsa_ifma_public's result on the words this function writes against
// rsa_mont64.c at every word count from 32 to 64, and bin/rsa_equiv_test
// holds the same step, inside r2_by_division, against rsa_mont.c's 32-bit
// arithmetic.
#include "harness.h"

uint64_t nondet_u64(void);

#include "rsa_mont.c"

#define VALUE_EXPONENT_MIN 64
#define VALUE_EXPONENT_MAX 131

// r = 2^exponent mod m for the two-word m, by doubling from 1. A doubling
// keeps the bit that leaves the top word, and subtracts m where the 129-bit
// value is at or above m; the 128-bit subtraction wraps on purpose there,
// to the 129-bit difference, which is below m.
static void power_by_doubling(uint64_t r[2], const uint64_t m[2], size_t exponent) {
    ct_u128 modulus = ((ct_u128)m[1] << 64) | m[0];
    ct_u128 value = 1;
    for (size_t i = 0; i < exponent; i++) {
        ct_u128 top = value >> 127;
        value <<= 1;
        if (top != 0 || value >= modulus) {
            value -= modulus;
        }
    }
    r[0] = (uint64_t)value;
    r[1] = (uint64_t)(value >> 64);
}

int main(void) {
    uint64_t m[2];
    m[0] = nondet_u64() | 1;
    m[1] = nondet_u64() | ((uint64_t)1 << 63);
    size_t exponent = nondet_size_t();
    __CPROVER_assume(exponent >= VALUE_EXPONENT_MIN && exponent <= VALUE_EXPONENT_MAX);
    uint64_t rem[2];
    power_of_two_mod(rem, m, 2, exponent);
    uint64_t expected[2];
    power_by_doubling(expected, m, exponent);
    __CPROVER_assert(rem[0] == expected[0] && rem[1] == expected[1],
                     "power_of_two_mod writes 2^exponent mod m");
    return 0;
}
