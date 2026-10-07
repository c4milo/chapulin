// The table of multiples of G, and the two formulas the wide scalar
// multiplications add to the complete addition, against p256_point.c and
// p256_field.c.
//
// run_table recomputes every entry of p256_wide_table from
// p256_point_generator. Row i starts at 16^i * G, four doublings above the
// row before, and steps through its odd multiples by adding twice that
// point: each entry must be the affine form of what p256_point_add and
// p256_point_affine give, byte for byte. No wide routine runs on either
// side of the comparison: the entry's limbs go through p256_field.c's own
// conversion out of the Montgomery domain. tools/p256_wide.py computed the
// table with Python's integers, so this holds the checked-in file to a
// second computation, in C, by the code the proofs and the vectors hold.
//
// run_formulas holds p256_wide_point_add_affine and p256_wide_point_double
// to p256_point_add:
//
//   the mixed addition computes the coordinates the complete addition
//   computes when the second point's Z is 1, so the two must agree limb for
//   limb on any coordinates at all, on a curve or not;
//
//   the doubling computes the same point as the complete addition of a
//   point with itself, in other coordinates, so the two must agree as
//   points: both at infinity, or the same affine bytes, and the doubling's
//   point at infinity must be (0 : Y : 0) with Y not zero. Its inputs are
//   multiples of G, with Z 1 and with a Z the additions before left, and
//   the point at infinity.
//
// Included by test/p256_equiv_test.c only, which declares the generator,
// report and the helpers this file uses.
#ifndef CH_P256_EQUIV_TABLE_H
#define CH_P256_EQUIV_TABLE_H

#include "p256_wide_table.h"

// One coordinate of a table entry as 32 big-endian bytes, by p256_field.c:
// the 64-bit limbs split in two, then out of the Montgomery domain.
static void table_coordinate_bytes(uint8_t out[P256_FE_LEN], const p256_wide_fe *coordinate) {
    p256_fe portable;
    for (size_t i = 0; i < P256_WIDE_FE_LIMBS; i++) {
        portable.limb[2 * i] = (uint32_t)coordinate->limb[i];
        portable.limb[2 * i + 1] = (uint32_t)(coordinate->limb[i] >> 32);
    }
    p256_fe_from_mont(&portable, &portable);
    p256_fe_to_bytes(out, &portable);
}

// Whether table entry [window][entry] is the affine form of multiple.
static int table_entry_is(size_t window, size_t entry, const p256_point *multiple) {
    uint8_t want_x[P256_FE_LEN];
    uint8_t want_y[P256_FE_LEN];
    uint8_t got_x[P256_FE_LEN];
    uint8_t got_y[P256_FE_LEN];
    uint32_t finite = p256_point_affine(want_x, want_y, multiple);
    table_coordinate_bytes(got_x, &p256_wide_table[window][entry].x);
    table_coordinate_bytes(got_y, &p256_wide_table[window][entry].y);
    return finite == UINT32_MAX && memcmp(want_x, got_x, sizeof got_x) == 0 &&
           memcmp(want_y, got_y, sizeof got_y) == 0;
}

static void run_table(void) {
    p256_point base = p256_point_generator; // 16^window * G
    for (size_t window = 0; window < P256_WIDE_TABLE_WINDOWS; window++) {
        p256_point twice;
        p256_point multiple = base; // (2 * entry + 1) * 16^window * G
        p256_point_add(&twice, &base, &base);
        for (size_t entry = 0; entry < P256_WIDE_TABLE_ENTRIES; entry++) {
            char name[64];
            (void)snprintf(name, sizeof name, "entry [%zu][%zu]", window, entry);
            report("table", name, table_entry_is(window, entry, &multiple));
            p256_point_add(&multiple, &multiple, &twice);
        }
        for (int doubling = 0; doubling < 4; doubling++) {
            p256_point_add(&base, &base, &base);
        }
    }
}

// a + b for b with Z = 1, in both files, in both shapes a caller uses.
static void add_affine_case(const char *name, const p256_point *a, const p256_fe *b_x,
                            const p256_fe *b_y) {
    p256_point b;
    p256_point want;
    p256_wide_point wide_a;
    p256_wide_point got;
    p256_wide_affine wide_b;
    b.x = *b_x;
    b.y = *b_y;
    b.z = p256_fe_one_mont;
    p256_point_add(&want, a, &b);
    p256_wide_point_from_portable(&wide_a, a);
    p256_wide_fe_from_portable(&wide_b.x, b_x);
    p256_wide_fe_from_portable(&wide_b.y, b_y);
    p256_wide_point_add_affine(&got, &wide_a, &wide_b);
    int ok = same_point(&got, &want);
    got = wide_a;
    p256_wide_point_add_affine(&got, &got, &wide_b);
    ok &= same_point(&got, &want);
    report("mixed add", name, ok);
}

static int wide_fe_is_zero(const p256_wide_fe *a) {
    uint64_t bits = 0;
    for (size_t i = 0; i < P256_WIDE_FE_LIMBS; i++) {
        bits |= a->limb[i];
    }
    return bits == 0;
}

// Whether p names a point: Z is not zero, or p is (0 : Y : 0) with Y not zero, the shape
// p256_wide_point.h gives the point at infinity. (0 : 0 : 0) names none, and an addition that
// reads it gives (0 : 0 : 0) back whatever it adds, while same_affine reads it as the point at
// infinity, since its Z is zero.
static int names_a_point(const p256_wide_point *p) {
    return !wide_fe_is_zero(&p->z) || (wide_fe_is_zero(&p->x) && !wide_fe_is_zero(&p->y));
}

// 2a in both files, as points, in both shapes a caller uses.
static void double_case(const char *name, const p256_point *a) {
    p256_point want;
    p256_point back;
    p256_wide_point wide_a;
    p256_wide_point got;
    p256_point_add(&want, a, a);
    p256_wide_point_from_portable(&wide_a, a);
    p256_wide_point_double(&got, &wide_a);
    p256_wide_point_to_portable(&back, &got);
    int ok = same_affine(&back, &want) && names_a_point(&got);
    got = wide_a;
    p256_wide_point_double(&got, &got);
    p256_wide_point_to_portable(&back, &got);
    ok &= same_affine(&back, &want) && names_a_point(&got);
    report("double", name, ok);
}

static void run_formulas(void) {
    p256_point a;
    p256_point b;
    p256_point negated;
    p256_scalar k;
    for (int i = 0; i < 3000; i++) {
        random_coordinates(&a);
        random_coordinates(&b);
        add_affine_case("random coordinates", &a, &b.x, &b.y);
    }
    // Points on the curve. a has a Z the additions of a multiplication left,
    // and the generator has Z = 1, which is what an affine operand is.
    random_wide_scalar(&k, 1);
    p256_point_base_mul(&a, &k);
    b = p256_point_generator;
    negated = b;
    p256_fe_neg(&negated.y, &negated.y);
    add_affine_case("a point and the generator", &a, &b.x, &b.y);
    add_affine_case("the generator and itself", &b, &b.x, &b.y);
    add_affine_case("the generator and its negative", &b, &negated.x, &negated.y);
    add_affine_case("infinity and the generator", &p256_point_infinity, &b.x, &b.y);

    double_case("infinity", &p256_point_infinity);
    double_case("the generator", &p256_point_generator);
    for (int i = 0; i < 24; i++) {
        random_wide_scalar(&k, (uint32_t)i & 1U);
        p256_point_base_mul(&a, &k);
        // Four in a row, as a multiplication doubles between windows.
        for (int doubling = 0; doubling < 4; doubling++) {
            double_case("a multiple of the generator", &a);
            p256_point_add(&a, &a, &a);
        }
    }
}

#endif
