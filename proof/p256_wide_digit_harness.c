// Proves, for the pieces of p256_wide_mul.c that read a scalar and a table,
// on their real bodies, over a fully nondet scalar and fully nondet table
// rows:
//
//   the digits add up to the scalar. For every k, the 64 digits window_digit
//   returns, each (2 index + 1) with its sign, times 16 to the window, sum
//   to k | 1 modulo 2^256. Both scalar multiplications rest on that sum, and
//   a digit read from the wrong bits, a sign taken from the wrong bit or a
//   top window that reads a bit past the scalar fails it. The sum runs in
//   the reference arithmetic of proof/p256_wide_reference.h, 128-bit sums
//   that cannot wrap;
//
//   every digit's index is below P256_WIDE_TABLE_ENTRIES, its sign mask is
//   0 or all ones, the top window's digit is positive, and every bit the
//   digit reads is inside the scalar: the shifts and the limb index are
//   proven in bounds for every window;
//
//   table_select and multiple_select return the row's entry at the index,
//   limb for limb, for every index below the row's length and any row
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
    for (size_t i = 0; i < P256_SCALAR_LIMBS; i++) {
        k->limb[i] = nondet_u32();
    }
}

static void prove_digits(void) {
    p256_scalar k;
    uint64_t sum[REF_LIMBS] = {0, 0, 0, 0};
    uint64_t want[REF_LIMBS];
    scalar_nondet(&k);
    for (size_t window = 0; window < WINDOWS; window++) {
        digit d = window_digit(&k, window);
        __CPROVER_assert(d.index < ENTRIES, "window_digit: the index is inside a row");
        __CPROVER_assert(d.negative == 0 || d.negative == UINT64_MAX,
                         "window_digit: the sign is a mask, 0 or all ones");
        __CPROVER_assert(window + 1 < WINDOWS || d.negative == 0,
                         "window_digit: the top window's digit is positive");
        // (2 index + 1) * 16^window, which fits its limb: the size is below
        // 16 and the shift at most 60.
        uint64_t term[REF_LIMBS] = {0, 0, 0, 0};
        term[window >> 4] = (2 * d.index + 1) << (WINDOW_BITS * (window & 15));
        if (d.negative != 0) {
            (void)ref_sub(sum, sum, term);
        } else {
            (void)ref_add(sum, sum, term);
        }
    }
    for (size_t i = 0; i < REF_LIMBS; i++) {
        want[i] = (uint64_t)k.limb[2 * i] | ((uint64_t)k.limb[2 * i + 1] << 32);
    }
    want[0] |= 1;
    __CPROVER_assert(limbs_same(sum, want), "the 64 digits add up to k | 1");
}

static void fe_nondet(p256_wide_fe *f) {
    for (size_t i = 0; i < P256_WIDE_FE_LIMBS; i++) {
        f->limb[i] = nondet_u64();
    }
}

// Each comparison below names its limb through the row's own members,
// row[index].y.limb[i]. cbmc 6.11.0 reads the wrong member through a pointer
// to a second member of an array element at a symbolic index: with
// `const uint64_t *p = row[index].y.limb`, it fails `p[0] ==
// row[index].y.limb[0]`. The code under test takes no such pointer: every
// row index in table_select and multiple_select is a loop counter.
static void prove_selects(void) {
    p256_wide_affine affine_row[ENTRIES];
    p256_wide_point point_row[ENTRIES];
    for (size_t j = 0; j < ENTRIES; j++) {
        fe_nondet(&affine_row[j].x);
        fe_nondet(&affine_row[j].y);
        fe_nondet(&point_row[j].x);
        fe_nondet(&point_row[j].y);
        fe_nondet(&point_row[j].z);
    }
    uint64_t index = nondet_u64();
    __CPROVER_assume(index < ENTRIES);

    p256_wide_affine affine;
    p256_wide_point point;
    table_select(&affine, affine_row, index);
    multiple_select(&point, point_row, index);
    for (size_t i = 0; i < P256_WIDE_FE_LIMBS; i++) {
        __CPROVER_assert(affine.x.limb[i] == affine_row[index].x.limb[i] &&
                             affine.y.limb[i] == affine_row[index].y.limb[i],
                         "table_select: the entry at the index, and no other");
        __CPROVER_assert(point.x.limb[i] == point_row[index].x.limb[i] &&
                             point.y.limb[i] == point_row[index].y.limb[i] &&
                             point.z.limb[i] == point_row[index].z.limb[i],
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
