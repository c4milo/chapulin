// The p256_field.h stubs every harness above the field shares. Each
// stub asserts the contract p256_field.h states for its arguments and
// havocs its output, so nothing a caller computes depends on a field
// value. The real bodies are proven in proof/p256_field_harness.c.
//
// This is the layering hkdf_harness.c uses, and the reason it exists is
// arithmetic size: one complete point addition runs 14 Montgomery
// products, each 64 widening products, and one scalar multiplication
// runs 512 additions. Unrolling that over the real bodies is the shape
// docs/proofs.md says returns no verdict.
#ifndef CH_PROOF_P256_FIELD_STUBS_H
#define CH_PROOF_P256_FIELD_STUBS_H

#include "harness.h"

#include "p256_field.h"

const p256_fe p256_fe_zero = {
    {0, 0, 0, 0, 0, 0, 0, 0}
};
// R mod p, the Montgomery form of 1, repeated from p256_field.c.
const p256_fe p256_fe_one_mont = {
    {0x00000001, 0x00000000, 0x00000000, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
     0x00000000}
};

#define STUB_W_OK(p, n) __CPROVER_assert(__CPROVER_w_ok(p, n), "field output writable")
#define STUB_R_OK(p, n) __CPROVER_assert(__CPROVER_r_ok(p, n), "field input readable")

static void havoc_fe(p256_fe *o) {
    STUB_W_OK(o, sizeof *o);
    for (size_t i = 0; i < P256_FE_LIMBS; i++) {
        o->limb[i] = nondet_u32();
    }
}

static void check_fe_readable(const p256_fe *a) {
    STUB_R_OK(a, sizeof *a);
}

void p256_fe_mul(p256_fe *o, const p256_fe *a, const p256_fe *b) {
    check_fe_readable(a);
    check_fe_readable(b);
    havoc_fe(o);
}

void p256_fe_sqr(p256_fe *o, const p256_fe *a) {
    check_fe_readable(a);
    havoc_fe(o);
}

void p256_fe_add(p256_fe *o, const p256_fe *a, const p256_fe *b) {
    check_fe_readable(a);
    check_fe_readable(b);
    havoc_fe(o);
}

void p256_fe_sub(p256_fe *o, const p256_fe *a, const p256_fe *b) {
    check_fe_readable(a);
    check_fe_readable(b);
    havoc_fe(o);
}

void p256_fe_neg(p256_fe *o, const p256_fe *a) {
    check_fe_readable(a);
    havoc_fe(o);
}

void p256_fe_inv(p256_fe *o, const p256_fe *a) {
    check_fe_readable(a);
    havoc_fe(o);
}

void p256_fe_to_mont(p256_fe *o, const p256_fe *a) {
    check_fe_readable(a);
    havoc_fe(o);
}

void p256_fe_from_mont(p256_fe *o, const p256_fe *a) {
    check_fe_readable(a);
    havoc_fe(o);
}

// The one assertion both harnesses keep: a caller that handed a 0-or-1
// value here, or a value with only some bits set, would be selecting
// with arithmetic that is not a mask.
void p256_fe_cmov(p256_fe *o, const p256_fe *a, uint32_t mask) {
    check_fe_readable(a);
    __CPROVER_assert(mask == 0 || mask == UINT32_MAX,
                     "p256_fe_cmov: the mask its caller builds is 0 or all ones");
    havoc_fe(o);
}

void p256_fe_cswap(p256_fe *a, p256_fe *b, uint32_t mask) {
    __CPROVER_assert(mask == 0 || mask == UINT32_MAX, "p256_fe_cswap: the mask is 0 or all ones");
    havoc_fe(a);
    havoc_fe(b);
}

void p256_fe_from_bytes(p256_fe *o, const uint8_t in[P256_FE_LEN]) {
    STUB_R_OK(in, P256_FE_LEN);
    havoc_fe(o);
}

void p256_fe_to_bytes(uint8_t out[P256_FE_LEN], const p256_fe *a) {
    STUB_W_OK(out, P256_FE_LEN);
    check_fe_readable(a);
    fill_nondet(out, P256_FE_LEN);
}

uint32_t p256_fe_reduced_mask(const p256_fe *a) {
    check_fe_readable(a);
    return nondet_mask();
}

uint32_t p256_fe_zero_mask(const p256_fe *a) {
    check_fe_readable(a);
    return nondet_mask();
}

uint32_t p256_fe_equal_mask(const p256_fe *a, const p256_fe *b) {
    check_fe_readable(a);
    check_fe_readable(b);
    return nondet_mask();
}

#endif
