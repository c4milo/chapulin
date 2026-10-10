// Proves: no sum in rsa_avx2.c's product wraps, at 2 and 3 groups, in the
// multiplication and in the square. The check is --unsigned-overflow-check
// on the launch line, which makes every unsigned +, - and * a property:
// each lane add of the rows of a and of m, each scalar sum and product of
// the triangle, the last pass of carries, and the index arithmetic.
//
// The lane products are the contract in proof/rsa_avx2_stubs.h, which
// rsa_avx2_lanes_harness.c discharges: each lane of a product of two lanes
// below 2^29 is at or below (2^29 - 1)^2.
//
// No launch line names this file. Each line runs one product, through the
// copy rsa_avx2.c holds for its digit width, from a file of its own that
// sets SUMS_GROUPS, SUMS_BITS and SUMS_SQUARE and includes this one:
//   rsa_avx2_sums_multiply_2   multiply_28 at 2 groups
//   rsa_avx2_sums_multiply_3   multiply_28 at 3 groups
//   rsa_avx2_sums_square_2     square_28 at 2 groups
//   rsa_avx2_sums_square_3     square_28 at 3 groups
// and the four _webpki lines the same for multiply_27 and square_27, which
// a build compiles under CH_TRUST_WEBPKI alone. The four products in one
// formula passed 8 GB in the solver; one at 3 groups takes 2.9 GB.
//
// The group count is a literal and the digit count any value that group
// count holds: 5 to 8 digits in 2 groups and 9 to 12 in 3. Every lane of
// the operands and of the modulus a product at 3 groups reads, lanes 0 to
// READ_LANES - 1, is any value below 2^D, which holds every number
// rsa_avx2_public gives a product and more: the real numbers hold zeros
// below digit 0 and from digit n up. The harness writes no lane above
// those, and cbmc reads an unwritten lane as any value, which covers every
// value a real number holds there. k0 is any value below 2^D, as the
// record masks it. Each product runs the aliasing shape rsa_avx2_public
// calls it in: the output on the second operand of a multiplication, as
// its first and last products write, and on the operand of a square.
//
// The group count is part of the argument. 2 groups run the first and the
// last group, the window's shift and the last group's write in place, and
// 3 a group between them; every other count runs the same statements more
// times. The bound at 19 to 38 groups is the one rsa_avx2.c's header
// states, which spec/lean/Spec/RsaAvx2.lean's lanes_fit proves of its
// model of the C at every digit count the C takes, and
// bin/rsa_avx2_model_test checks every digit of each product along the
// public operation at every word count from 32 to 64.
#include "rsa_avx2_stubs.h"

#include "rsa_avx2.c"

// The lanes a product at 3 groups reads of a number: the views of
// registers 0 to 3 read up to lane PAD + 4 * 3 + 3.
#define READ_LANES (PAD + 4 * 4)

// A modulus record of D-bit digits for a group count, with the digit count
// any value that group count holds.
static void havoc_record(rsa_avx2_modulus *modulus, size_t groups, unsigned bits) {
    havoc_digits(modulus->digits, READ_LANES, bits);
    modulus->k0 = nondet_u64() & (((uint64_t)1 << bits) - 1);
    size_t digit_count = nondet_size_t();
    __CPROVER_assume(digit_count > 4 * (groups - 1) && digit_count <= 4 * groups);
    modulus->digit_count = digit_count;
    modulus->groups = groups;
    modulus->bits = bits;
}

#if !defined(SUMS_GROUPS) || !defined(SUMS_BITS) || !defined(SUMS_SQUARE)
#error "each rsa_avx2_sums line sets SUMS_GROUPS, SUMS_BITS and SUMS_SQUARE"
#endif

int main(void) {
    rsa_avx2_modulus modulus;
    uint64_t a[NUMBER_LANES];
    uint64_t power[NUMBER_LANES];
    havoc_record(&modulus, SUMS_GROUPS, SUMS_BITS);
    havoc_digits(a, READ_LANES, SUMS_BITS);
    havoc_digits(power, READ_LANES, SUMS_BITS);
#if SUMS_SQUARE && SUMS_BITS == 27
    square_27(power, power, &modulus);
#elif SUMS_SQUARE
    square_28(power, power, &modulus);
#elif SUMS_BITS == 27
    multiply_27(power, a, power, &modulus);
#else
    multiply_28(power, a, power, &modulus);
#endif
    return 0;
}
