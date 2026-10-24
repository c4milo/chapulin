// Proves: one addition of a table entry and one doubling of x25519_wide_edwards.h, each
// followed by to_extended(), keep every word of the point inside INV-34's bounds, starting from
// any point inside them, as the key generation's loops run them (docs/decisions.md 148). The
// entry comes from select_entry() over a row whose words are under 2^51, as every word of the
// shipped table is (tools/x25519_wide.py checks it), for any digit in [-8, 8]: y + x and y - x
// under 2^51, and 2dxy or 2p - 2dxy under 2^52.
// Each step hands ct_mul128 only operands inside the contract's domain, wraps no unsigned value
// (--unsigned-overflow-check, which covers every sum, every a + 2p - b and every a + 4p - b),
// and leaves every word of the sum it hands to_extended() under 2^54, the bound the proofs of
// mul and sqr take for an operand.
//
// The invariant is proof/x25519_wide_stubs.h's: words 0, 2, 3 and 4 under 2^51 and word 1
// under 2^51 + 2^20. Base case, by inspection of x25519_wide_base_mul(): the identity, (0, 1,
// 1, 0). Step, proven here: an addition or a doubling from any point inside the bounds. The
// loops of x25519_wide_base_mul() run 64 additions and four doublings, so induction carries the
// bounds through them. The tail takes Z + Y and Z - Y and carries the second twice: the last
// block proves the forms, one invert() takes and one mul takes. x25519_wide_invert proves
// invert() on the first, and x25519_wide_tail proves mul and pack on what follows.
//
// The multiply is the contract in proof/x25519_wide_stubs.h, which x25519_wide_mul128
// discharges on the real ct_mul128.
#include "x25519_wide_stubs.h"

#define OPERAND ((uint64_t)1 << 54)

static void assume_point(edwards_point *p) {
    assume_state(p->x);
    assume_state(p->y);
    assume_state(p->z);
    assume_state(p->t);
}

// cbmc takes a string literal alone as an assertion's text, so these are macros.
#define ASSERT_POINT(p, what)                                                                      \
    do {                                                                                           \
        ASSERT_STATE((p)->x, what);                                                                \
        ASSERT_STATE((p)->y, what);                                                                \
        ASSERT_STATE((p)->z, what);                                                                \
        ASSERT_STATE((p)->t, what);                                                                \
    } while (0)

#define ASSERT_OPERANDS(s, what)                                                                   \
    do {                                                                                           \
        for (size_t i = 0; i < 5; i++) {                                                           \
            __CPROVER_assert((s)->e[i] < OPERAND && (s)->h[i] < OPERAND && (s)->g[i] < OPERAND &&  \
                                 (s)->f[i] < OPERAND,                                              \
                             what);                                                                \
        }                                                                                          \
    } while (0)

int main(void) {
    edwards_point added;
    edwards_point doubled;
    edwards_entry entry;
    edwards_sum sum;

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
    assume_point(&added);
    select_entry(&entry, (const uint64_t (*)[3][5])row, digit);
    add_entry(&sum, &added, &entry);
    ASSERT_OPERANDS(&sum, "an addition hands to_extended words under 2^54");
    to_extended(&added, &sum);
    ASSERT_POINT(&added, "an addition leaves the point inside INV-34's bounds");

    assume_point(&doubled);
    double_point(&sum, &doubled);
    ASSERT_OPERANDS(&sum, "a doubling hands to_extended words under 2^54");
    to_extended(&doubled, &sum);
    ASSERT_POINT(&doubled, "a doubling leaves the point inside INV-34's bounds");

    // The tail's sums, from a point inside the bounds.
    fe numerator;
    fe denominator;
    assume_point(&added);
    add(numerator, added.z, added.y);
    sub(denominator, added.z, added.y);
    carry_words(denominator);
    carry_words(denominator);
    for (size_t i = 0; i < 5; i++) {
        __CPROVER_assert(numerator[i] < OPERAND, "Z + Y has words under 2^54");
    }
    ASSERT_STATE(denominator, "Z - Y, carried twice, is in the form invert() takes");
    return 0;
}
