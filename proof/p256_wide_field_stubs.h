// The p256_wide_field.h stubs the harnesses above the wide field share:
// proof/p256_wide_point_harness.c and proof/p256_wide_mul_harness.c. Each
// stub asserts the contract p256_wide_field.h states for its arguments and
// havocs its output, so nothing a caller computes depends on a field value.
// It is proof/p256_field_stubs.h one field over, for the same reason: one
// complete point addition runs 14 Montgomery products, and a formula that
// unrolled them over the real bodies would return no verdict. The real
// bodies are proven in proof/p256_wide_field_harness.c,
// proof/p256_wide_field_mul_harness.c and proof/p256_wide_field_inv_harness.c.
//
// Every output is stored through the element's own type, never a byte fill
// of one (docs/proofs.md).
#ifndef CH_PROOF_P256_WIDE_FIELD_STUBS_H
#define CH_PROOF_P256_WIDE_FIELD_STUBS_H

#include "harness.h"

#include "p256_wide_field.h"

uint64_t nondet_u64(void);

// R mod p, the Montgomery form of 1, repeated from p256_wide_field.c.
const p256_wide_fe p256_wide_fe_one_mont = {
    {UINT64_C(0x0000000000000001), UINT64_C(0xffffffff00000000), UINT64_C(0xffffffffffffffff),
     UINT64_C(0x00000000fffffffe)}
};

#define STUB_W_OK(p, n) __CPROVER_assert(__CPROVER_w_ok(p, n), "wide field output writable")
#define STUB_R_OK(p, n) __CPROVER_assert(__CPROVER_r_ok(p, n), "wide field input readable")

// An unconstrained mask in this field's convention: 0 for false and
// UINT64_MAX for true.
static uint64_t nondet_wide_mask(void) {
    uint64_t m = nondet_u64();
    __CPROVER_assume(m == 0 || m == UINT64_MAX);
    return m;
}

static void havoc_wide_fe(p256_wide_fe *o) {
    STUB_W_OK(o, sizeof *o);
    for (size_t i = 0; i < P256_WIDE_FE_LIMBS; i++) {
        o->limb[i] = nondet_u64();
    }
}

static void check_wide_fe_readable(const p256_wide_fe *a) {
    STUB_R_OK(a, sizeof *a);
}

void p256_wide_fe_from_portable(p256_wide_fe *o, const p256_fe *a) {
    STUB_R_OK(a, sizeof *a);
    havoc_wide_fe(o);
}

void p256_wide_fe_to_portable(p256_fe *o, const p256_wide_fe *a) {
    check_wide_fe_readable(a);
    STUB_W_OK(o, sizeof *o);
    for (size_t i = 0; i < P256_FE_LIMBS; i++) {
        o->limb[i] = nondet_u32();
    }
}

void p256_wide_fe_from_bytes(p256_wide_fe *o, const uint8_t in[P256_FE_LEN]) {
    STUB_R_OK(in, P256_FE_LEN);
    havoc_wide_fe(o);
}

void p256_wide_fe_to_bytes(uint8_t out[P256_FE_LEN], const p256_wide_fe *a) {
    STUB_W_OK(out, P256_FE_LEN);
    check_wide_fe_readable(a);
    fill_nondet(out, P256_FE_LEN);
}

uint64_t p256_wide_fe_reduced_mask(const p256_wide_fe *a) {
    check_wide_fe_readable(a);
    return nondet_wide_mask();
}

uint64_t p256_wide_fe_zero_mask(const p256_wide_fe *a) {
    check_wide_fe_readable(a);
    return nondet_wide_mask();
}

uint64_t p256_wide_fe_equal_mask(const p256_wide_fe *a, const p256_wide_fe *b) {
    check_wide_fe_readable(a);
    check_wide_fe_readable(b);
    return nondet_wide_mask();
}

// The one assertion the harnesses keep: a caller that handed a 0-or-1 value
// here, or a value with only some bits set, would be selecting with
// arithmetic that is not a mask.
void p256_wide_fe_cmov(p256_wide_fe *o, const p256_wide_fe *a, uint64_t mask) {
    check_wide_fe_readable(a);
    __CPROVER_assert(mask == 0 || mask == UINT64_MAX,
                     "p256_wide_fe_cmov: the mask its caller builds is 0 or all ones");
    havoc_wide_fe(o);
}

void p256_wide_fe_add(p256_wide_fe *o, const p256_wide_fe *a, const p256_wide_fe *b) {
    check_wide_fe_readable(a);
    check_wide_fe_readable(b);
    havoc_wide_fe(o);
}

void p256_wide_fe_sub(p256_wide_fe *o, const p256_wide_fe *a, const p256_wide_fe *b) {
    check_wide_fe_readable(a);
    check_wide_fe_readable(b);
    havoc_wide_fe(o);
}

void p256_wide_fe_neg(p256_wide_fe *o, const p256_wide_fe *a) {
    check_wide_fe_readable(a);
    havoc_wide_fe(o);
}

void p256_wide_fe_mul(p256_wide_fe *o, const p256_wide_fe *a, const p256_wide_fe *b) {
    check_wide_fe_readable(a);
    check_wide_fe_readable(b);
    havoc_wide_fe(o);
}

void p256_wide_fe_sqr(p256_wide_fe *o, const p256_wide_fe *a) {
    check_wide_fe_readable(a);
    havoc_wide_fe(o);
}

void p256_wide_fe_to_mont(p256_wide_fe *o, const p256_wide_fe *a) {
    check_wide_fe_readable(a);
    havoc_wide_fe(o);
}

void p256_wide_fe_from_mont(p256_wide_fe *o, const p256_wide_fe *a) {
    check_wide_fe_readable(a);
    havoc_wide_fe(o);
}

void p256_wide_fe_inv(p256_wide_fe *o, const p256_wide_fe *a) {
    check_wide_fe_readable(a);
    havoc_wide_fe(o);
}

#endif
