// The wide P-256 field and scalar arithmetic against p256_field.c and
// p256_scalar.c, routine by routine, for test/p256_equiv_test.c. Both
// fields keep an element in the Montgomery domain with R = 2^256, so each
// wide routine must give the words the routine it mirrors gives, taken two
// at a time: every comparison here is of the words, not of a value read
// back through another routine.
//
// The wide field also answers test/p256_field_vectors.h directly, the
// values Python computed, so it is not checked only through the other
// field.
//
// Included by test/p256_equiv_test.c only, which declares the generator,
// report, the failure count and the comparison count this file uses.
#ifndef CH_P256_EQUIV_FIELD_H
#define CH_P256_EQUIV_FIELD_H

#define WIDE_ONES UINT64_MAX
#define PORTABLE_ONES UINT32_MAX

// Whether the wide element holds the portable element's words.
static int same_fe(const p256_wide_fe *wide, const p256_fe *portable) {
    p256_fe back;
    p256_wide_fe_to_portable(&back, wide);
    return memcmp(&back, portable, sizeof back) == 0;
}

// Whether a wide mask and a portable mask say the same thing, each all
// ones or zero.
static int same_mask(uint64_t wide, uint32_t portable) {
    return (wide == WIDE_ONES && portable == PORTABLE_ONES) || (wide == 0 && portable == 0);
}

// Eight words for a field element or a scalar: random, with one word in
// four all ones and one in four zero, so carries and borrows run the
// length of the value.
static void random_words(uint32_t word[8]) {
    for (size_t i = 0; i < 8; i++) {
        uint64_t r = rng_next();
        word[i] = (uint32_t)(r >> 32);
        if ((r & 3) == 0) {
            word[i] = UINT32_MAX;
        } else if ((r & 3) == 1) {
            word[i] = 0;
        }
    }
}

// An element below p.
static void random_fe(p256_fe *o) {
    do {
        random_words(o->word);
    } while (p256_fe_reduced_mask(o) == 0);
}

// One pair of elements through every routine of both fields.
static void field_case(const char *name, const p256_fe *a, const p256_fe *b, int with_inverse) {
    p256_wide_fe wa;
    p256_wide_fe wb;
    p256_wide_fe wo;
    p256_fe po;
    int ok = 1;
    p256_wide_fe_from_portable(&wa, a);
    p256_wide_fe_from_portable(&wb, b);
    ok &= same_fe(&wa, a);

    p256_fe_add(&po, a, b);
    p256_wide_fe_add(&wo, &wa, &wb);
    ok &= same_fe(&wo, &po);
    p256_fe_sub(&po, a, b);
    p256_wide_fe_sub(&wo, &wa, &wb);
    ok &= same_fe(&wo, &po);
    p256_fe_neg(&po, a);
    p256_wide_fe_neg(&wo, &wa);
    ok &= same_fe(&wo, &po);
    p256_fe_mul(&po, a, b);
    p256_wide_fe_mul(&wo, &wa, &wb);
    ok &= same_fe(&wo, &po);
    p256_fe_sqr(&po, a);
    p256_wide_fe_sqr(&wo, &wa);
    ok &= same_fe(&wo, &po);
    p256_fe_to_mont(&po, a);
    p256_wide_fe_to_mont(&wo, &wa);
    ok &= same_fe(&wo, &po);
    p256_fe_from_mont(&po, a);
    p256_wide_fe_from_mont(&wo, &wa);
    ok &= same_fe(&wo, &po);
    if (with_inverse) {
        p256_fe_inv(&po, a);
        p256_wide_fe_inv(&wo, &wa);
        ok &= same_fe(&wo, &po);
    }

    // The output over each input, the shapes the point formulas write.
    p256_fe_mul(&po, a, b);
    wo = wa;
    p256_wide_fe_mul(&wo, &wo, &wb);
    ok &= same_fe(&wo, &po);
    wo = wb;
    p256_wide_fe_mul(&wo, &wa, &wo);
    ok &= same_fe(&wo, &po);
    p256_fe_sub(&po, a, b);
    wo = wb;
    p256_wide_fe_sub(&wo, &wa, &wo);
    ok &= same_fe(&wo, &po);

    ok &= same_mask(p256_wide_fe_zero_mask(&wa), p256_fe_zero_mask(a));
    ok &= same_mask(p256_wide_fe_equal_mask(&wa, &wb), p256_fe_equal_mask(a, b));
    ok &= same_mask(p256_wide_fe_equal_mask(&wa, &wa), p256_fe_equal_mask(a, a));

    // Both masks through the select.
    wo = wa;
    p256_wide_fe_cmov(&wo, &wb, 0);
    ok &= same_fe(&wo, a);
    p256_wide_fe_cmov(&wo, &wb, WIDE_ONES);
    ok &= same_fe(&wo, b);

    // The byte marshalling, through the other field's bytes.
    uint8_t portable_bytes[P256_FE_LEN];
    uint8_t wide_bytes[P256_FE_LEN];
    p256_fe_to_bytes(portable_bytes, a);
    p256_wide_fe_to_bytes(wide_bytes, &wa);
    ok &= memcmp(portable_bytes, wide_bytes, P256_FE_LEN) == 0;
    p256_wide_fe_from_bytes(&wo, portable_bytes);
    ok &= same_fe(&wo, a);
    report("field", name, ok);
}

// The reduction boundary and the predicates on values that are not
// elements: reduced_mask must agree on every 256-bit value.
static void reduced_case(const p256_fe *any) {
    p256_wide_fe wide;
    p256_wide_fe_from_portable(&wide, any);
    report("field", "reduced_mask on any 256-bit value",
           same_mask(p256_wide_fe_reduced_mask(&wide), p256_fe_reduced_mask(any)));
}

// Elements at the edges, as words: 0, 1, 2, p - 1, p - 2, R mod p, p - 2^192 and 2^255. Then
// three values that are not elements: p, p + 1 and 2^256 - 1.
static const p256_fe FE_EDGES[] = {
    {{0, 0, 0, 0, 0, 0, 0, 0}},
    {{1, 0, 0, 0, 0, 0, 0, 0}},
    {{2, 0, 0, 0, 0, 0, 0, 0}},
    {{0xfffffffe, 0xffffffff, 0xffffffff, 0, 0, 0, 1, 0xffffffff}},
    {{0xfffffffd, 0xffffffff, 0xffffffff, 0, 0, 0, 1, 0xffffffff}},
    {{1, 0, 0, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0}},
    {{0xffffffff, 0xffffffff, 0xffffffff, 0, 0, 0, 0, 0xffffffff}},
    {{0, 0, 0, 0, 0, 0, 0, 0x80000000}},
};
static const p256_fe NOT_ELEMENTS[] = {
    {{0xffffffff, 0xffffffff, 0xffffffff, 0, 0, 0, 1, 0xffffffff}},
    {{0, 0, 0, 1, 0, 0, 1, 0xffffffff}},
    {{0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
      0xffffffff}},
};
#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static void run_field(void) {
    for (size_t i = 0; i < COUNT(FE_EDGES); i++) {
        for (size_t j = 0; j < COUNT(FE_EDGES); j++) {
            field_case("edge elements", &FE_EDGES[i], &FE_EDGES[j], 1);
        }
        reduced_case(&FE_EDGES[i]);
    }
    for (size_t i = 0; i < COUNT(NOT_ELEMENTS); i++) {
        reduced_case(&NOT_ELEMENTS[i]);
    }
    for (int i = 0; i < 20000; i++) {
        p256_fe a;
        p256_fe b;
        random_fe(&a);
        random_fe(&b);
        field_case("random elements", &a, &b, i < 200);
        random_words(a.word);
        reduced_case(&a);
    }
    report("field", "the Montgomery form of 1", same_fe(&p256_wide_fe_one_mont, &p256_fe_one_mont));
}

// The wide field on the values Python computed.
static int wide_bytes_are(const p256_wide_fe *a, const uint8_t want[P256_FE_LEN]) {
    uint8_t got[P256_FE_LEN];
    p256_wide_fe_to_bytes(got, a);
    return memcmp(got, want, sizeof got) == 0;
}

static void run_field_vectors(void) {
    for (size_t i = 0; i < COUNT(P256_FIELD_CASES); i++) {
        const p256_field_case *c = &P256_FIELD_CASES[i];
        p256_wide_fe a;
        p256_wide_fe b;
        p256_wide_fe got;
        int ok = 1;
        p256_wide_fe_from_bytes(&a, c->a);
        p256_wide_fe_from_bytes(&b, c->b);
        p256_wide_fe_add(&got, &a, &b);
        ok &= wide_bytes_are(&got, c->sum);
        p256_wide_fe_sub(&got, &a, &b);
        ok &= wide_bytes_are(&got, c->diff);
        p256_wide_fe_mul(&got, &a, &b);
        ok &= wide_bytes_are(&got, c->mont_product);
        p256_wide_fe_to_mont(&a, &a);
        p256_wide_fe_to_mont(&b, &b);
        p256_wide_fe_mul(&got, &a, &b);
        p256_wide_fe_from_mont(&got, &got);
        ok &= wide_bytes_are(&got, c->product);
        report("field vectors", c->name, ok);
    }
    for (size_t i = 0; i < COUNT(P256_FIELD_INV_CASES); i++) {
        const p256_field_inv_case *c = &P256_FIELD_INV_CASES[i];
        p256_wide_fe a;
        p256_wide_fe_from_bytes(&a, c->a);
        p256_wide_fe_to_mont(&a, &a);
        p256_wide_fe_inv(&a, &a);
        p256_wide_fe_from_mont(&a, &a);
        report("field vectors", c->name, wide_bytes_are(&a, c->inverse));
    }
}

// A scalar below n.
static void random_scalar(p256_scalar *o) {
    do {
        random_words(o->word);
    } while (p256_scalar_reduced_mask(o) == 0);
}

static void scalar_case(const char *name, const p256_scalar *a, const p256_scalar *b,
                        int with_inverse) {
    p256_scalar portable;
    p256_scalar wide;
    int ok = 1;
    p256_scalar_mul(&portable, a, b);
    p256_wide_scalar_mul(&wide, a, b);
    ok &= memcmp(&portable, &wide, sizeof wide) == 0;
    // The output over each input, as p256_sign.c never writes it and a
    // later caller may.
    wide = *a;
    p256_wide_scalar_mul(&wide, &wide, b);
    ok &= memcmp(&portable, &wide, sizeof wide) == 0;
    wide = *b;
    p256_wide_scalar_mul(&wide, a, &wide);
    ok &= memcmp(&portable, &wide, sizeof wide) == 0;
    if (with_inverse) {
        p256_scalar_inverse(&portable, a);
        p256_wide_scalar_inverse(&wide, a);
        ok &= memcmp(&portable, &wide, sizeof wide) == 0;
        wide = *a;
        p256_wide_scalar_inverse(&wide, &wide);
        ok &= memcmp(&portable, &wide, sizeof wide) == 0;
    }
    report("scalar", name, ok);
}

// 0, 1, 2, n - 1, n - 2 and 2^255, as words.
static const p256_scalar SCALAR_EDGES[] = {
    {{0, 0, 0, 0, 0, 0, 0, 0}},
    {{1, 0, 0, 0, 0, 0, 0, 0}},
    {{2, 0, 0, 0, 0, 0, 0, 0}},
    {{0xfc632550, 0xf3b9cac2, 0xa7179e84, 0xbce6faad, 0xffffffff, 0xffffffff, 0, 0xffffffff}},
    {{0xfc63254f, 0xf3b9cac2, 0xa7179e84, 0xbce6faad, 0xffffffff, 0xffffffff, 0, 0xffffffff}},
    {{0, 0, 0, 0, 0, 0, 0, 0x80000000}},
};

static void run_scalar(void) {
    for (size_t i = 0; i < COUNT(SCALAR_EDGES); i++) {
        for (size_t j = 0; j < COUNT(SCALAR_EDGES); j++) {
            scalar_case("edge scalars", &SCALAR_EDGES[i], &SCALAR_EDGES[j], 1);
        }
    }
    for (int i = 0; i < 20000; i++) {
        p256_scalar a;
        p256_scalar b;
        random_scalar(&a);
        random_scalar(&b);
        scalar_case("random scalars", &a, &b, i < 200);
    }
}

#endif
