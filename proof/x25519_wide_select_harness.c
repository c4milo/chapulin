// Proves: the digits and the scan of x25519_wide_edwards.h, on their real bodies
// (docs/decisions.md 148).
//
// recode(): for every clamped scalar s, each of the 64 digits is in [-8, 8], and the digits add
// up to s: e_0 + 16 e_1 + ... + 16^63 e_63 = s. The harness reads the digits back from the
// bottom: v_i = e_i + c_i with c_0 = 0, the nibble n_i = v_i mod 16 and c_(i+1) = (v_i - n_i) /
// 16. Then e_i 16^i = (n_i + 16 c_(i+1) - c_i) 16^i, and the sum telescopes to the sum of the
// n_i 16^i plus c_64 16^64. Each n_i is nibble i of s and c_64 is zero, so the digits add up to
// s.
//
// select_entry(): for every row whose words are under 2^51, as every word of the shipped table
// is (tools/x25519_wide.py checks it), and every digit in [-8, 8], the entry is the row's entry
// at the digit's size for a positive digit, the identity (1, 1, 0) for zero, and for a negative
// digit the row's entry with y + x and y - x swapped and 2dxy taken to 2p - 2dxy: the entry of
// the negative point. Word for word, so the scan keeps exactly one entry and the masks select
// nothing else. The row is unconstrained beyond the word bound, so the proof covers every row
// of the table. A row of the shipped table at a symbolic index took more memory than the
// runner gives a proof.
#include "harness.h"

#include "x25519_wide.c"

uint64_t nondet_u64(void);

static void prove_recode(void) {
    uint8_t clamped[X25519_LEN];
    for (size_t i = 0; i < X25519_LEN; i++) {
        clamped[i] = nondet_u8();
    }
    clamped[0] &= 248;
    clamped[31] = (uint8_t)((clamped[31] & 127) | 64);
    int64_t e[DIGITS];
    recode(e, clamped);
    int64_t carry = 0;
    for (size_t i = 0; i < DIGITS; i++) {
        __CPROVER_assert(e[i] >= -8 && e[i] <= 8, "recode: every digit is in [-8, 8]");
        int64_t value = e[i] + carry;
        int64_t nibble = ((value % 16) + 16) % 16;
        carry = (value - nibble) / 16;
        int64_t want = (clamped[i / 2] >> (4 * (i % 2))) & 15;
        __CPROVER_assert(nibble == want, "recode: the digits add up to s, nibble by nibble");
    }
    __CPROVER_assert(carry == 0, "recode: the digits add up to s, with nothing above 16^64");
}

// Each comparison names its word through the row's own subscripts, row[size - 1][...][w], as
// proof/p256_wide_digit_harness.c does, rather than through a pointer into the row.
static void prove_select(void) {
    uint64_t row[X25519_WIDE_TABLE_ENTRIES][3][5];
    for (size_t j = 0; j < X25519_WIDE_TABLE_ENTRIES; j++) {
        for (size_t element = 0; element < 3; element++) {
            for (size_t w = 0; w < 5; w++) {
                row[j][element][w] = nondet_u64() >> 13;
            }
        }
    }
    int64_t digit = (int64_t)nondet_u64();
    __CPROVER_assume(digit >= -8 && digit <= 8);
    edwards_entry o;
    for (size_t w = 0; w < 5; w++) {
        o.y_plus_x[w] = nondet_u64();
        o.y_minus_x[w] = nondet_u64();
        o.xy2d[w] = nondet_u64();
    }
    select_entry(&o, (const uint64_t (*)[3][5])row, digit);
    size_t size = (size_t)(digit < 0 ? -digit : digit);
    for (size_t w = 0; w < 5; w++) {
        if (digit == 0) {
            uint64_t one = w == 0 ? 1 : 0;
            __CPROVER_assert(o.y_plus_x[w] == one && o.y_minus_x[w] == one && o.xy2d[w] == 0,
                             "select_entry: a zero digit gives the identity");
        } else if (digit > 0) {
            __CPROVER_assert(o.y_plus_x[w] == row[size - 1][0][w] &&
                                 o.y_minus_x[w] == row[size - 1][1][w] &&
                                 o.xy2d[w] == row[size - 1][2][w],
                             "select_entry: a positive digit gives the row's entry");
        } else {
            __CPROVER_assert(o.y_plus_x[w] == row[size - 1][1][w] &&
                                 o.y_minus_x[w] == row[size - 1][0][w] &&
                                 o.xy2d[w] == TWO_P[w] - row[size - 1][2][w],
                             "select_entry: a negative digit gives the entry's negative");
        }
    }
}

int main(void) {
    prove_recode();
    prove_select();
    return 0;
}
