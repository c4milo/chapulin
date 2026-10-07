// Proves, for p256_wide_verify_point.c's signed digits:
//
//   signed_digits    : any 256-bit scalar, on its real body. The count it
//                      returns is at most DIGITS_LEN, every digit is zero
//                      or odd in [-15, 15], and the digits past the count
//                      are zero
//   add_g_multiple,
//   add_q_multiple   : any digit signed_digits can write, onto any point,
//                      so the index into row 0 of the table of multiples
//                      of G and into the table of the key's multiples is
//                      in bounds
//
// The three are what p256_wide_jacobian_double_mul's loop reads its arrays
// through, and proof/p256_wide_verify_point_harness.c states what else
// that loop runs. The field's routines are the contracts of
// proof/p256_wide_field_stubs.h, and the launch line links
// p256_wide_table.c.
//
// Not proven here: that the digits spell the scalar, k = sum of digits[i]
// * 2^i. bin/p256_verify_equiv_test holds the verdict the digits lead to
// against p256.c's, with scalars at their edges.
#include "p256_wide_field_stubs.h"

#include "p256_wide_verify_point.c"

int nondet_int(void);

static void havoc_point(p256_wide_jacobian *p) {
    havoc_wide_fe(&p->x);
    havoc_wide_fe(&p->y);
    havoc_wide_fe(&p->z);
}

int main(void) {
    p256_wide_jacobian a;
    p256_wide_jacobian table[TABLE_LEN];
    p256_scalar k;
    int8_t digits[DIGITS_LEN];
    for (size_t i = 0; i < P256_SCALAR_WORDS; i++) {
        k.word[i] = nondet_u32();
    }
    int len = signed_digits(digits, &k);
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
        add_q_multiple(&a, table, digit);
        havoc_point(&a);
        add_g_multiple(&a, digit);
    }
    return 0;
}
