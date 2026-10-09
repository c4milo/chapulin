// Proves: no sum in rsa_ifma.c's almost-Montgomery product or in
// normalize_digits wraps, at 1 and 2 registers. The check is
// --unsigned-overflow-check on the launch line, which makes every unsigned
// +, - and * a property: each lane add of a multiplication's half, each
// add of normalize_digits' carries, the scalar sum of add_round's two
// products and digit_zero in 128 bits, and digit_zero's add of the lane
// that moves into lane 0.
//
// The products are the contracts in proof/rsa_ifma_stubs.h, which
// rsa_ifma_lanes_harness.c and rsa_mont64_mul128_harness.c discharge: a
// lane multiplication adds any value below 2^52 to each lane, and the
// scalar product of two digits is any value below 2^104. Under them the
// bounds are the ones rsa_ifma.c's header states: a round adds four
// pieces below 2^52 to a lane, and the scalar sum stays below 2^106.
//
// Each product runs through almost_montgomery_product_core with the
// register count a literal, as each of the file's copies calls it, and
// with the digit count any value that register count holds: 1 to 8 digits
// in 1 register and 9 to 16 in 2. The operands' and the modulus's digits
// are any values below 2^52, the digits rsa_ifma_public gives them, and
// m0inv any value below 2^52, as the record masks it. Each register count
// runs the two aliasing shapes rsa_ifma_public calls: the output on the
// second operand, as its first and last products write, and all three the
// same array, as its squares do.
//
// normalize_digits also runs alone at 1 and 2 registers over lanes that
// are any 64-bit values, so the claim holds for any lanes it is given,
// not only for the ones a product leaves.
//
// The register count is part of the argument for the lanes. A lane holds
// only what was added since its contents entered the top lane, at most as
// many rounds ago as the sum has lanes, and a round adds four pieces below
// 2^52, so a sum of 80 lanes, the most, holds lanes below
// 4 * 80 * 2^52 < 2^61. 1 and 2 registers run every statement of a product
// in every position it takes but the middle registers of a longer sum,
// whose statements are the same, and 2 registers run the carries between
// registers in both the product and normalize_digits. The bound at 5 to 10
// registers is that argument, which rsa_ifma.c's header states, and
// bin/rsa_ifma_model_test checks every digit of each product along the
// public operation at every word count from 32 to 64. One product at 10
// registers and 79 digits, in one aliasing shape, wrote 58 million clauses
// under this line's flags, and was not run.
#include "rsa_ifma_stubs.h"

#include "rsa_ifma.c"

// A modulus record whose digits and m0inv are any values below 2^52, with
// digit_count any value register_count registers hold.
static void havoc_record(rsa_ifma_modulus *modulus, size_t register_count) {
    havoc_digits(modulus->digits, LANE_COUNT_MAX);
    modulus->m0inv = nondet_u64() & STUB_DIGIT_MASK;
    size_t digit_count = nondet_size_t();
    __CPROVER_assume(digit_count > DIGITS_PER_REGISTER * (register_count - 1) &&
                     digit_count <= DIGITS_PER_REGISTER * register_count);
    modulus->digit_count = digit_count;
    modulus->registers = register_count;
}

static void prove_product(size_t register_count) {
    rsa_ifma_modulus modulus;
    uint64_t a[LANE_COUNT_MAX];
    uint64_t power[LANE_COUNT_MAX];

    havoc_record(&modulus, register_count);
    havoc_digits(a, LANE_COUNT_MAX);
    havoc_digits(power, LANE_COUNT_MAX);
    almost_montgomery_product_core(power, a, power, &modulus, register_count);

    havoc_record(&modulus, register_count);
    havoc_digits(power, LANE_COUNT_MAX);
    almost_montgomery_product_core(power, power, power, &modulus, register_count);
}

static void prove_normalize(size_t register_count) {
    rsa_ifma_lanes sum[RSA_IFMA_REGISTERS_MAX];
    for (size_t i = 0; i < register_count; i++) {
        for (int j = 0; j < 8; j++) {
            sum[i].lane[j] = nondet_u64();
        }
    }
    normalize_digits(sum, register_count);
}

int main(void) {
    prove_product(1);
    prove_product(2);
    prove_normalize(1);
    prove_normalize(2);
    return 0;
}
