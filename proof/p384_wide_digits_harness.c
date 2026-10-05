// Proves, for p384_wide_point.c's signed digits:
//
//   signed_digits : any 384-bit scalar, on its real body. The count it
//                   returns is at most DIGITS_LEN, every digit is zero or
//                   odd in [-15, 15], and the digits past the count are
//                   zero
//   add_multiple  : any digit signed_digits can write, in any table and
//                   onto any point, so the table index is in bounds
//
// The two are what p384_wide_double_mul's loop reads its arrays through,
// and proof/p384_wide_point_harness.c states what else that loop runs.
// The field's product, sum and difference are the contracts of
// proof/p384_wide_stubs.h.
//
// Not proven here: that the digits spell the scalar, k = sum of
// digits[i] * 2^i. bin/p384_equiv_test holds the verdict the digits lead
// to against p384.c's, with scalars chosen either side of a window and
// just under n.
#include "p384_wide_stubs.h"

#include "p384_wide_point.c"

int main(void) {
    p384_wide_point a;
    p384_wide_point table[TABLE_LEN];
    uint64_t k[LIMBS];
    int8_t digits[DIGITS_LEN];
    for (size_t i = 0; i < LIMBS; i++) {
        k[i] = nondet_u64();
    }
    int len = signed_digits(digits, k);
    __CPROVER_assert(len >= 0 && len <= DIGITS_LEN, "signed_digits: the count fits the array");
    int at = nondet_int();
    __CPROVER_assume(at >= 0 && at < DIGITS_LEN);
    int digit = digits[at];
    __CPROVER_assert(digit == 0 || (digit % 2 != 0 && digit >= -15 && digit <= 15),
                     "signed_digits: a digit is zero or odd in [-15, 15]");
    __CPROVER_assert(at < len || digit == 0, "signed_digits: the digits past the count are zero");
    if (digit != 0) {
        for (size_t i = 0; i < TABLE_LEN; i++) {
            havoc_point(&table[i]);
        }
        havoc_point(&a);
        add_multiple(&a, table, digit);
    }
    return 0;
}
