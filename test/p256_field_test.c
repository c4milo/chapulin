// Constant-time P-256 field arithmetic against vectors Python computed
// (test/gen_p256_field_vectors.py), plus the boundaries and the aliasing
// shapes the point code will use. Its own binary, out of the packaged
// object like sha3 and p384: nothing links p256_field.c until the
// P-256 key exchange lands.
//
// The vectors are the independent answer; what this file adds is the
// cases a generator cannot express. The reduction boundary gets both
// sides (the last element works, the prime itself and the first value
// past it are refused), every routine runs with its output aliasing an
// input, and the masked choices run under both masks.
#include <stdio.h>
#include <string.h>

#include "p256_field.h"
#include "p256_field_vectors.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

#define ALL_ONES 0xffffffffU

// p itself, the first value that is not an element.
static const uint8_t P_BYTES[32] = {
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static int bytes_are(const p256_fe *a, const uint8_t want[32]) {
    uint8_t got[32];
    p256_fe_to_bytes(got, a);
    return memcmp(got, want, sizeof got) == 0;
}

static void load(p256_fe *o, const uint8_t in[32]) {
    p256_fe_from_bytes(o, in);
}

// The arithmetic of one generated case, in the plain and the Montgomery
// domain.
static void run_case(const p256_field_case *c) {
    p256_fe a;
    p256_fe b;
    p256_fe got;
    load(&a, c->a);
    load(&b, c->b);
    CHECK(p256_fe_reduced_mask(&a) == ALL_ONES);
    CHECK(p256_fe_reduced_mask(&b) == ALL_ONES);
    CHECK(bytes_are(&a, c->a)); // from_bytes and to_bytes round trip

    p256_fe_add(&got, &a, &b);
    CHECK(bytes_are(&got, c->sum));
    p256_fe_sub(&got, &a, &b);
    CHECK(bytes_are(&got, c->diff));

    // The Montgomery product of the raw limbs is a*b/R mod p.
    p256_fe_mul(&got, &a, &b);
    CHECK(bytes_are(&got, c->mont_product));

    // Into the domain, one product, back out: the plain product.
    p256_fe a_mont;
    p256_fe b_mont;
    p256_fe_to_mont(&a_mont, &a);
    p256_fe_to_mont(&b_mont, &b);
    p256_fe_mul(&got, &a_mont, &b_mont);
    p256_fe_from_mont(&got, &got);
    CHECK(bytes_are(&got, c->product));

    // A square is the product of a value with itself, so the cases whose
    // two operands are equal carry the answer for p256_fe_sqr too.
    p256_fe squared;
    p256_fe_sqr(&squared, &a_mont);
    p256_fe_mul(&got, &a_mont, &a_mont);
    CHECK(memcmp(&squared, &got, sizeof squared) == 0);
    if (memcmp(c->a, c->b, 32) == 0) {
        p256_fe_from_mont(&got, &squared);
        CHECK(bytes_are(&got, c->product));
    }

    // a + (-a) is zero for every element, zero included.
    p256_fe negated;
    p256_fe_neg(&negated, &a);
    p256_fe_add(&got, &a, &negated);
    CHECK(p256_fe_zero_mask(&got) == ALL_ONES);
}

// The output aliasing an input, the shape a point routine writes.
static void run_aliasing(const p256_field_case *c) {
    p256_fe a;
    p256_fe b;
    p256_fe want;
    p256_fe got;
    load(&a, c->a);
    load(&b, c->b);

    got = a;
    p256_fe_add(&got, &got, &b);
    CHECK(bytes_are(&got, c->sum));
    got = b;
    p256_fe_add(&got, &a, &got);
    CHECK(bytes_are(&got, c->sum));
    got = a;
    p256_fe_sub(&got, &got, &b);
    CHECK(bytes_are(&got, c->diff));
    got = b;
    p256_fe_sub(&got, &a, &got);
    CHECK(bytes_are(&got, c->diff));
    got = a;
    p256_fe_mul(&got, &got, &b);
    CHECK(bytes_are(&got, c->mont_product));
    got = b;
    p256_fe_mul(&got, &a, &got);
    CHECK(bytes_are(&got, c->mont_product));

    // Both operands one object, which is what sqr does.
    p256_fe_mul(&want, &a, &a);
    got = a;
    p256_fe_sqr(&got, &got);
    CHECK(memcmp(&got, &want, sizeof got) == 0);

    // Negation in place.
    p256_fe_neg(&want, &a);
    got = a;
    p256_fe_neg(&got, &got);
    CHECK(memcmp(&got, &want, sizeof got) == 0);
}

static void run_inverse(const p256_field_inv_case *c) {
    p256_fe a;
    p256_fe a_mont;
    p256_fe got;
    load(&a, c->a);
    p256_fe_to_mont(&a_mont, &a);
    p256_fe_inv(&got, &a_mont);
    p256_fe_from_mont(&got, &got);
    CHECK(bytes_are(&got, c->inverse));

    // a * a^-1 is one, except for zero, which has no inverse and gives
    // zero rather than a branch.
    p256_fe product;
    p256_fe_inv(&product, &a_mont);
    p256_fe_mul(&product, &product, &a_mont);
    if (p256_fe_zero_mask(&a) == ALL_ONES) {
        CHECK(p256_fe_zero_mask(&product) == ALL_ONES);
    } else {
        CHECK(p256_fe_equal_mask(&product, &p256_fe_one_mont) == ALL_ONES);
    }

    // The inverse with the output aliasing the input.
    got = a_mont;
    p256_fe_inv(&got, &got);
    p256_fe_inv(&product, &a_mont);
    CHECK(memcmp(&got, &product, sizeof got) == 0);
}

// The exact reduction boundary: the last element is an element, the
// prime itself and the value after it are not.
static void test_boundary(void) {
    uint8_t bytes[32];
    p256_fe a;

    memcpy(bytes, P_BYTES, sizeof bytes);
    bytes[31] = 0xfe; // p - 1
    load(&a, bytes);
    CHECK(p256_fe_reduced_mask(&a) == ALL_ONES);

    load(&a, P_BYTES); // p
    CHECK(p256_fe_reduced_mask(&a) == 0);

    // p + 1: p's low twelve bytes are 0xff, so the carry walks through
    // them and sets the zero byte above them.
    memcpy(bytes, P_BYTES, sizeof bytes);
    memset(bytes + 20, 0, 12);
    bytes[19] = 0x01;
    load(&a, bytes);
    CHECK(p256_fe_reduced_mask(&a) == 0);

    memset(bytes, 0xff, sizeof bytes); // 2^256 - 1, the largest 32 bytes
    load(&a, bytes);
    CHECK(p256_fe_reduced_mask(&a) == 0);

    memset(bytes, 0, sizeof bytes); // zero is an element
    load(&a, bytes);
    CHECK(p256_fe_reduced_mask(&a) == ALL_ONES);
    CHECK(p256_fe_zero_mask(&a) == ALL_ONES);

    // -0 is 0, and -1 is p-1.
    p256_fe negated;
    p256_fe_neg(&negated, &a);
    CHECK(p256_fe_zero_mask(&negated) == ALL_ONES);
    bytes[31] = 1;
    load(&a, bytes);
    p256_fe_neg(&negated, &a);
    memcpy(bytes, P_BYTES, sizeof bytes);
    bytes[31] = 0xfe;
    CHECK(bytes_are(&negated, bytes));
}

static void test_masks(void) {
    p256_fe a;
    p256_fe b;
    p256_fe copy_a;
    p256_fe copy_b;
    uint8_t bytes[32];

    memset(bytes, 0, sizeof bytes);
    bytes[31] = 7;
    load(&a, bytes);
    bytes[31] = 9;
    load(&b, bytes);
    CHECK(p256_fe_equal_mask(&a, &a) == ALL_ONES);
    CHECK(p256_fe_equal_mask(&a, &b) == 0);
    CHECK(p256_fe_zero_mask(&a) == 0);

    // A zero mask moves nothing; an all-ones mask moves everything.
    copy_a = a;
    p256_fe_cmov(&copy_a, &b, 0);
    CHECK(p256_fe_equal_mask(&copy_a, &a) == ALL_ONES);
    p256_fe_cmov(&copy_a, &b, ALL_ONES);
    CHECK(p256_fe_equal_mask(&copy_a, &b) == ALL_ONES);

    copy_a = a;
    copy_b = b;
    p256_fe_cswap(&copy_a, &copy_b, 0);
    CHECK(p256_fe_equal_mask(&copy_a, &a) == ALL_ONES);
    CHECK(p256_fe_equal_mask(&copy_b, &b) == ALL_ONES);
    p256_fe_cswap(&copy_a, &copy_b, ALL_ONES);
    CHECK(p256_fe_equal_mask(&copy_a, &b) == ALL_ONES);
    CHECK(p256_fe_equal_mask(&copy_b, &a) == ALL_ONES);
}

// The two exported constants are what they claim: zero, and R mod p.
static void test_constants(void) {
    p256_fe one;
    uint8_t bytes[32];
    CHECK(p256_fe_zero_mask(&p256_fe_zero) == ALL_ONES);
    p256_fe_from_mont(&one, &p256_fe_one_mont);
    memset(bytes, 0, sizeof bytes);
    bytes[31] = 1;
    CHECK(bytes_are(&one, bytes));
    // Entering the domain from 1 lands on the same constant.
    p256_fe_from_bytes(&one, bytes);
    p256_fe_to_mont(&one, &one);
    CHECK(p256_fe_equal_mask(&one, &p256_fe_one_mont) == ALL_ONES);
}

int main(void) {
    for (size_t i = 0; i < sizeof P256_FIELD_CASES / sizeof P256_FIELD_CASES[0]; i++) {
        run_case(&P256_FIELD_CASES[i]);
        run_aliasing(&P256_FIELD_CASES[i]);
    }
    for (size_t i = 0; i < sizeof P256_FIELD_INV_CASES / sizeof P256_FIELD_INV_CASES[0]; i++) {
        run_inverse(&P256_FIELD_INV_CASES[i]);
    }
    test_boundary();
    test_masks();
    test_constants();
    if (failures == 0) {
        (void)printf("p256_field: all tests passed\n");
    }
    return failures != 0;
}
