// The p256_point.h stubs every harness above the point arithmetic
// shares: proof/p256_sign_harness.c and proof/p256_ecdh_harness.c. Each
// stub asserts the contract p256_point.h states for its arguments and
// havocs its output, so nothing a caller computes depends on a
// coordinate. The real bodies are proven in proof/p256_point_harness.c
// and proof/p256_point_ladder_harness.c.
//
// This is what keeps both formulas solvable. p256_sign and p256_ecdh
// each run one scalar multiplication, which is 512 complete point
// additions; a proof that unrolled them over the real bodies returns no
// verdict, which proof/run.sh's history for this module records.
//
// Every output is stored through the point's own type, never a byte fill
// of one, which is what docs/proofs.md asks for: a byte fill writes the
// padding a p256_point may carry and reads back as an object the type
// system never produced.
#ifndef CH_PROOF_P256_POINT_STUBS_H
#define CH_PROOF_P256_POINT_STUBS_H

#include "harness.h"

#include "p256_point.h"

const p256_point p256_point_infinity = {
    {{0, 0, 0, 0, 0, 0, 0, 0}},
    {{0, 0, 0, 0, 0, 0, 0, 0}},
    {{0, 0, 0, 0, 0, 0, 0, 0}},
};

const p256_point p256_point_generator = {
    {{0, 0, 0, 0, 0, 0, 0, 0}},
    {{0, 0, 0, 0, 0, 0, 0, 0}},
    {{0, 0, 0, 0, 0, 0, 0, 0}},
};

static void havoc_point(p256_point *o) {
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof *o), "point output writable");
    for (size_t i = 0; i < P256_FE_LIMBS; i++) {
        o->x.limb[i] = nondet_u32();
        o->y.limb[i] = nondet_u32();
        o->z.limb[i] = nondet_u32();
    }
}

void p256_point_add(p256_point *o, const p256_point *a, const p256_point *b) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a), "add: first point readable");
    __CPROVER_assert(__CPROVER_r_ok(b, sizeof *b), "add: second point readable");
    havoc_point(o);
}

void p256_point_cswap(p256_point *a, p256_point *b, uint32_t mask) {
    __CPROVER_assert(mask == 0 || mask == UINT32_MAX, "cswap: the mask is 0 or all ones");
    havoc_point(a);
    havoc_point(b);
}

void p256_point_mul(p256_point *o, const p256_scalar *k, const p256_point *p) {
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k), "mul: scalar readable");
    __CPROVER_assert(__CPROVER_r_ok(p, sizeof *p), "mul: point readable");
    havoc_point(o);
}

void p256_point_base_mul(p256_point *o, const p256_scalar *k) {
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k), "base_mul: scalar readable");
    havoc_point(o);
}

uint32_t p256_point_from_bytes(p256_point *o, const uint8_t in[P256_POINT_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(in, P256_POINT_LEN), "from_bytes: input readable");
    havoc_point(o);
    return nondet_mask();
}

uint32_t p256_point_affine(uint8_t x[P256_FE_LEN], uint8_t y[P256_FE_LEN], const p256_point *a) {
    __CPROVER_assert(__CPROVER_w_ok(x, P256_FE_LEN), "affine: x writable");
    __CPROVER_assert(y == NULL || __CPROVER_w_ok(y, P256_FE_LEN), "affine: y writable or absent");
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a), "affine: point readable");
    fill_nondet(x, P256_FE_LEN);
    if (y != NULL) {
        fill_nondet(y, P256_FE_LEN);
    }
    return nondet_mask();
}

uint32_t p256_point_affine_x(uint8_t out[P256_FE_LEN], const p256_point *a) {
    return p256_point_affine(out, NULL, a);
}

#endif
