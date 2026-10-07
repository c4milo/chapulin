// Proves, for the pieces of p256_wide_mul.c that read a scalar and a table,
// on their real bodies, over a fully nondet scalar and fully nondet table
// rows:
//
//   the digits add up to the scalar, at both widths. For every k, the 64
//   four-bit digits window_digit returns for p256_wide_mul, and the 43
//   six-bit digits it returns for p256_wide_base_mul, each (2 index + 1)
//   with its sign, times 2 to its window's lowest bit, sum to k | 1 modulo
//   2^256. Both scalar multiplications rest on that sum, and a digit read
//   from the wrong bits, a sign taken from the wrong bit or a top window
//   that reads a bit past the scalar fails it. The sum runs in the
//   reference arithmetic of proof/p256_wide_reference.h, 128-bit sums that
//   cannot wrap;
//
//   every digit's index is below the length of its row, its sign mask is 0
//   or all ones, the top window's digit is positive, and every bit the digit
//   reads is inside the scalar: the shifts and the word index are proven in
//   bounds for every window;
//
//   table_select and multiple_select return the row's entry at the index,
//   word for word, for every index below the row's length and any row
//   contents. A scan that skips an entry, stops early or keeps two entries
//   fails here;
//
//   equal_mask gives all ones exactly when its two values are the same, for
//   any two 64-bit values, and wraps nothing (--unsigned-overflow-check on
//   the launch line).
//
// Not proven here, and not a claim a formula over values can state: that
// the scan reads every entry whatever the index holds. The code reads
// row[j] for every j of a loop whose count is a literal, and
// lint-wide-multiply holds the file's conditional branches at its ceiling.
#include "harness.h"

#include "p256_wide_reference.h"

#include "p256_wide_mul.c"

static void scalar_nondet(p256_scalar *k) {
    for (size_t i = 0; i < P256_SCALAR_WORDS; i++) {
        k->word[i] = nondet_u32();
    }
}

// term = value * 2^shift in four 64-bit words, for value below 2^8 and shift below 256: the
// word the shift names, and the bits that cross into the word above.
static void shifted(uint64_t term[REF_WORDS], uint64_t value, size_t shift) {
    size_t word = shift >> 6;
    size_t bit = shift & 63;
    for (size_t i = 0; i < REF_WORDS; i++) {
        term[i] = 0;
    }
    term[word] = value << bit;
    if (bit != 0 && word + 1 < REF_WORDS) {
        term[word + 1] = value >> (64 - bit);
    }
}

// The digits of k at one width, bits wide, windows of them, each index below entries.
static void prove_digits_of(size_t bits, size_t windows, uint64_t entries) {
    p256_scalar k;
    uint64_t sum[REF_WORDS] = {0, 0, 0, 0};
    uint64_t want[REF_WORDS];
    scalar_nondet(&k);
    for (size_t window = 0; window < windows; window++) {
        digit d = window_digit(&k, window, bits, windows);
        __CPROVER_assert(d.index < entries, "window_digit: the index is inside a row");
        __CPROVER_assert(d.negative == 0 || d.negative == UINT64_MAX,
                         "window_digit: the sign is a mask, 0 or all ones");
        __CPROVER_assert(window + 1 < windows || d.negative == 0,
                         "window_digit: the top window's digit is positive");
        // (2 index + 1) * 2^(bits window), below 2^256: the top window's index is below 8, so
        // its term is below 2^256 at both widths.
        uint64_t term[REF_WORDS];
        shifted(term, 2 * d.index + 1, bits * window);
        if (d.negative != 0) {
            (void)ref_sub(sum, sum, term);
        } else {
            (void)ref_add(sum, sum, term);
        }
    }
    for (size_t i = 0; i < REF_WORDS; i++) {
        want[i] = (uint64_t)k.word[2 * i] | ((uint64_t)k.word[2 * i + 1] << 32);
    }
    want[0] |= 1;
    __CPROVER_assert(words_same(sum, want), "the digits add up to k | 1");
}

static void prove_digits(void) {
    prove_digits_of(WINDOW_BITS, WINDOWS, ENTRIES);
    prove_digits_of(P256_WIDE_TABLE_WINDOW_BITS, P256_WIDE_TABLE_WINDOWS, P256_WIDE_TABLE_ENTRIES);
}

static void fe_nondet(p256_wide_fe *f) {
    for (size_t i = 0; i < P256_WIDE_FE_WORDS; i++) {
        f->word[i] = nondet_u64();
    }
}

// Each comparison below names its word through the row's own members,
// row[index].y.word[i]. cbmc 6.11.0 reads the wrong member through a pointer
// to a second member of an array element at a symbolic index: with
// `const uint64_t *p = row[index].y.word`, it fails `p[0] ==
// row[index].y.word[0]`. The code under test takes no such pointer: every
// row index in table_select and multiple_select is a loop counter.
static void prove_selects(void) {
    p256_wide_affine affine_row[P256_WIDE_TABLE_ENTRIES];
    p256_wide_point point_row[ENTRIES];
    for (size_t j = 0; j < P256_WIDE_TABLE_ENTRIES; j++) {
        fe_nondet(&affine_row[j].x);
        fe_nondet(&affine_row[j].y);
    }
    for (size_t j = 0; j < ENTRIES; j++) {
        fe_nondet(&point_row[j].x);
        fe_nondet(&point_row[j].y);
        fe_nondet(&point_row[j].z);
    }
    uint64_t entry_index = nondet_u64();
    uint64_t multiple_index = nondet_u64();
    __CPROVER_assume(entry_index < P256_WIDE_TABLE_ENTRIES);
    __CPROVER_assume(multiple_index < ENTRIES);

    p256_wide_affine affine;
    p256_wide_point point;
    table_select(&affine, affine_row, entry_index);
    multiple_select(&point, point_row, multiple_index);
    for (size_t i = 0; i < P256_WIDE_FE_WORDS; i++) {
        __CPROVER_assert(affine.x.word[i] == affine_row[entry_index].x.word[i] &&
                             affine.y.word[i] == affine_row[entry_index].y.word[i],
                         "table_select: the entry at the index, and no other");
        __CPROVER_assert(point.x.word[i] == point_row[multiple_index].x.word[i] &&
                             point.y.word[i] == point_row[multiple_index].y.word[i] &&
                             point.z.word[i] == point_row[multiple_index].z.word[i],
                         "multiple_select: the multiple at the index, and no other");
    }
}

static void prove_equal_mask(void) {
    uint64_t a = nondet_u64();
    uint64_t b = nondet_u64();
    __CPROVER_assert(equal_mask(a, b) == (a == b ? UINT64_MAX : 0),
                     "equal_mask: all ones for the same value and nothing else");
}

int main(void) {
    prove_digits();
    prove_selects();
    prove_equal_mask();
    return 0;
}
