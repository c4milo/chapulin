// The table of multiples of G, and the three formulas the wide scalar
// multiplications add to the complete addition, against p256_point.c and
// p256_field.c.
//
// run_table recomputes every entry of p256_wide_table from
// p256_point_generator. Row i starts at 2^(6i) * G, six doublings above
// the row before, and steps through its odd multiples by adding twice that
// point: each entry must be the affine form of what p256_point_add and
// p256_point_affine give, byte for byte. No wide routine runs on either
// side of the comparison: the entry's words go through p256_field.c's own
// conversion out of the Montgomery domain. tools/p256_wide.py computed the
// table with Python's integers, so this holds the checked-in file to a
// second computation, in C, by the code the proofs and the vectors hold.
//
// run_formulas holds p256_wide_point_add_affine,
// p256_wide_point_add_affine_incomplete and the four Jacobian routines to
// p256_point_add:
//
//   the mixed addition computes the coordinates the complete addition
//   computes when the second point's Z is 1, so the two must agree word for
//   word on any coordinates at all, on a curve or not;
//
//   the incomplete addition computes the same point as the complete one in
//   other coordinates, where the first point is finite and its x is not the
//   second's, so the two must agree as points there. Its inputs are
//   multiples of G with a Z the additions before left, and entries of the
//   table. Outside that condition it must give what p256_wide_point.h
//   states: (0 : 0 : 0) for a point and itself and for the point at
//   infinity, and the point at infinity for a point and its negative;
//
//   the Jacobian doubling and the incomplete Jacobian addition compute the
//   same points as the complete addition, in other coordinates, so each
//   answer, moved back to homogeneous coordinates by
//   p256_wide_point_from_jacobian, must agree with it as a point: both at
//   infinity, or the same affine bytes, and a point at infinity must come
//   back as (0 : Y : 0) with Y not zero. Their inputs are multiples of G,
//   with Z 1 and with a Z the additions before left, moved to Jacobian
//   coordinates by p256_wide_point_to_jacobian, and the point at infinity.
//   Outside the incomplete addition's condition its Z must be zero, as
//   p256_wide_point.h states.
//
// Included by test/p256_equiv_test.c only, which declares the generator,
// report and the helpers this file uses.
#ifndef CH_P256_EQUIV_TABLE_H
#define CH_P256_EQUIV_TABLE_H

#include "p256_wide_table.h"

// One coordinate of a table entry as 32 big-endian bytes, by p256_field.c:
// the 64-bit words split in two, then out of the Montgomery domain.
static void table_coordinate_bytes(uint8_t out[P256_FE_LEN], const p256_wide_fe *coordinate) {
    p256_fe portable;
    for (size_t i = 0; i < P256_WIDE_FE_WORDS; i++) {
        portable.word[2 * i] = (uint32_t)coordinate->word[i];
        portable.word[2 * i + 1] = (uint32_t)(coordinate->word[i] >> 32);
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
    p256_point base = p256_point_generator; // 2^(6 window) * G
    for (size_t window = 0; window < P256_WIDE_TABLE_WINDOWS; window++) {
        p256_point twice;
        p256_point multiple = base; // (2 * entry + 1) * 2^(6 window) * G
        p256_point_add(&twice, &base, &base);
        for (size_t entry = 0; entry < P256_WIDE_TABLE_ENTRIES; entry++) {
            char name[64];
            (void)snprintf(name, sizeof name, "entry [%zu][%zu]", window, entry);
            report("table", name, table_entry_is(window, entry, &multiple));
            p256_point_add(&multiple, &multiple, &twice);
        }
        for (int doubling = 0; doubling < P256_WIDE_TABLE_WINDOW_BITS; doubling++) {
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
    for (size_t i = 0; i < P256_WIDE_FE_WORDS; i++) {
        bits |= a->word[i];
    }
    return bits == 0;
}

// What the incomplete addition gives for a + b, in both shapes a caller uses: zero in every
// coordinate where zeros is set, and otherwise want as a point, with Z not zero where
// finite is set and as (0 : Y : 0) with Y not zero where it is not.
typedef struct {
    int zeros;
    int finite;
} incomplete_answer;

static int incomplete_answer_is(const p256_wide_point *got, const p256_point *want,
                                incomplete_answer answer) {
    if (answer.zeros) {
        return wide_fe_is_zero(&got->x) && wide_fe_is_zero(&got->y) && wide_fe_is_zero(&got->z);
    }
    p256_point back;
    p256_wide_point_to_portable(&back, got);
    int named = answer.finite ? !wide_fe_is_zero(&got->z)
                              : wide_fe_is_zero(&got->x) && !wide_fe_is_zero(&got->y) &&
                                    wide_fe_is_zero(&got->z);
    return named && same_affine(&back, want);
}

static void add_affine_incomplete_case(const char *name, const p256_point *a,
                                       const p256_wide_affine *b, incomplete_answer answer) {
    p256_point portable_b;
    p256_point want;
    p256_wide_point wide_a;
    p256_wide_point got;
    p256_wide_fe_to_portable(&portable_b.x, &b->x);
    p256_wide_fe_to_portable(&portable_b.y, &b->y);
    portable_b.z = p256_fe_one_mont;
    p256_point_add(&want, a, &portable_b);
    p256_wide_point_from_portable(&wide_a, a);
    p256_wide_point_add_affine_incomplete(&got, &wide_a, b);
    int ok = incomplete_answer_is(&got, &want, answer);
    got = wide_a;
    p256_wide_point_add_affine_incomplete(&got, &got, b);
    ok &= incomplete_answer_is(&got, &want, answer);
    report("incomplete add", name, ok);
}

// The incomplete addition on multiples of G whose x differ, and on the three shapes outside
// its condition.
static void run_incomplete(void) {
    static const incomplete_answer SUM = {0, 1};
    static const incomplete_answer ZEROS = {1, 0};
    static const incomplete_answer INFINITY_POINT = {0, 0};
    p256_point a;
    p256_point generator_scaled;
    p256_wide_affine b;
    p256_wide_affine generator;
    p256_scalar k;
    p256_fe scale;
    for (int i = 0; i < 24; i++) {
        size_t window = (size_t)(i * 7) % P256_WIDE_TABLE_WINDOWS;
        size_t entry = (size_t)(i * 5) % P256_WIDE_TABLE_ENTRIES;
        random_wide_scalar(&k, (uint32_t)i & 1U);
        p256_point_base_mul(&a, &k);
        add_affine_incomplete_case("a multiple of G and a table entry", &a,
                                   &p256_wide_table[window][entry], SUM);
    }
    generator = p256_wide_table[0][0];
    // G with a Z that is not 1: each coordinate times the same element.
    for (size_t i = 0; i < P256_FE_WORDS; i++) {
        scale.word[i] = 0x9e3779b9U * (uint32_t)(i + 1);
    }
    generator_scaled = p256_point_generator;
    p256_fe_mul(&generator_scaled.x, &generator_scaled.x, &scale);
    p256_fe_mul(&generator_scaled.y, &generator_scaled.y, &scale);
    p256_fe_mul(&generator_scaled.z, &generator_scaled.z, &scale);
    add_affine_incomplete_case("G and itself", &generator_scaled, &generator, ZEROS);
    add_affine_incomplete_case("infinity and G", &p256_point_infinity, &generator, ZEROS);
    b = generator;
    p256_wide_fe_neg(&b.y, &b.y);
    add_affine_incomplete_case("G and its negative", &generator_scaled, &b, INFINITY_POINT);
}

// Whether p names a point: Z is not zero, or p is (0 : Y : 0) with Y not zero, the shape
// p256_wide_point.h gives the point at infinity. (0 : 0 : 0) names none, and an addition that
// reads it gives (0 : 0 : 0) back whatever it adds, while same_affine reads it as the point at
// infinity, since its Z is zero.
static int names_a_point(const p256_wide_point *p) {
    return !wide_fe_is_zero(&p->z) || (wide_fe_is_zero(&p->x) && !wide_fe_is_zero(&p->y));
}

// a in Jacobian coordinates, through p256_wide_point_to_jacobian.
static void jacobian_of(p256_wide_jacobian *o, const p256_point *a) {
    p256_wide_point wide;
    p256_wide_point_from_portable(&wide, a);
    p256_wide_point_to_jacobian(o, &wide);
}

// Whether the Jacobian point got is want: moved back by p256_wide_point_from_jacobian, it names
// a point, and it is want as a point.
static int jacobian_is(const p256_wide_jacobian *got, const p256_point *want) {
    p256_wide_point wide;
    p256_point back;
    p256_wide_point_from_jacobian(&wide, got);
    p256_wide_point_to_portable(&back, &wide);
    return names_a_point(&wide) && same_affine(&back, want);
}

// a through both conversions comes back as a, as a point.
static void jacobian_round_trip_case(const char *name, const p256_point *a) {
    p256_wide_jacobian jacobian;
    jacobian_of(&jacobian, a);
    report("jacobian round trip", name, jacobian_is(&jacobian, a));
}

// 2a in both files, as points, in both shapes a caller uses.
static void double_case(const char *name, const p256_point *a) {
    p256_point want;
    p256_wide_jacobian wide_a;
    p256_wide_jacobian got;
    p256_point_add(&want, a, a);
    jacobian_of(&wide_a, a);
    p256_wide_point_double_jacobian(&got, &wide_a);
    int ok = jacobian_is(&got, &want);
    got = wide_a;
    p256_wide_point_double_jacobian(&got, &got);
    ok &= jacobian_is(&got, &want);
    report("double", name, ok);
}

// a + b by the incomplete Jacobian addition, in the three shapes a caller uses: the sum the
// complete addition computes where sum is set, and Z = 0 where it is not.
static void add_jacobian_incomplete_case(const char *name, const p256_point *a, const p256_point *b,
                                         int sum) {
    p256_point want;
    p256_wide_jacobian wide_a;
    p256_wide_jacobian wide_b;
    p256_wide_jacobian got;
    p256_point_add(&want, a, b);
    jacobian_of(&wide_a, a);
    jacobian_of(&wide_b, b);
    int ok = 1;
    for (int shape = 0; shape < 3; shape++) {
        if (shape == 0) {
            p256_wide_point_add_jacobian_incomplete(&got, &wide_a, &wide_b);
        } else if (shape == 1) {
            got = wide_a;
            p256_wide_point_add_jacobian_incomplete(&got, &got, &wide_b);
        } else {
            got = wide_b;
            p256_wide_point_add_jacobian_incomplete(&got, &wide_a, &got);
        }
        ok &= sum ? jacobian_is(&got, &want) : wide_fe_is_zero(&got.z);
    }
    report("jacobian incomplete add", name, ok);
}

// The incomplete Jacobian addition on multiples of G whose x differ, on the odd multiples of a
// point that p256_wide_mul computes first, and on the shapes outside its condition.
static void run_jacobian(void) {
    p256_point a;
    p256_point b;
    p256_point twice;
    p256_point negated;
    p256_scalar k;
    for (int i = 0; i < 24; i++) {
        random_wide_scalar(&k, (uint32_t)i & 1U);
        p256_point_base_mul(&a, &k);
        random_wide_scalar(&k, (uint32_t)(i + 1) & 1U);
        p256_point_base_mul(&b, &k);
        add_jacobian_incomplete_case("two multiples of G", &a, &b, 1);
        jacobian_round_trip_case("a multiple of G", &a);
    }
    // (2j + 1) a = (2j - 1) a + 2a, for j from 1 to 7.
    random_wide_scalar(&k, 1);
    p256_point_base_mul(&a, &k);
    p256_point_add(&twice, &a, &a);
    b = a;
    for (int j = 1; j < 8; j++) {
        add_jacobian_incomplete_case("an odd multiple and twice the point", &b, &twice, 1);
        p256_point_add(&b, &b, &twice);
    }
    negated = a;
    p256_fe_neg(&negated.y, &negated.y);
    add_jacobian_incomplete_case("a point and its negative", &a, &negated, 1);
    add_jacobian_incomplete_case("infinity and infinity", &p256_point_infinity,
                                 &p256_point_infinity, 1);
    add_jacobian_incomplete_case("a point and itself", &a, &a, 0);
    add_jacobian_incomplete_case("infinity and a point", &p256_point_infinity, &a, 0);
    add_jacobian_incomplete_case("a point and infinity", &a, &p256_point_infinity, 0);
    jacobian_round_trip_case("the generator", &p256_point_generator);
    jacobian_round_trip_case("infinity", &p256_point_infinity);
    // A Jacobian point at infinity may have Y = 0: the conversion back must still name a point.
    p256_wide_jacobian zeros = {0};
    report("jacobian round trip", "every coordinate zero",
           jacobian_is(&zeros, &p256_point_infinity));
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

    run_incomplete();
    run_jacobian();

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
