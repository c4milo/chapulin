// The p256_wide_point.h stubs proof/p256_wide_mul_harness.c runs the scalar
// multiplications over. Each stub asserts that its inputs are readable and
// havocs its output, so nothing a multiplication computes depends on a
// coordinate. The real bodies are proven in proof/p256_wide_point_harness.c.
//
// Why this exists: one scalar multiplication runs hundreds of point
// formulas, each of them more than forty field calls, and a formula that
// unrolled them returned no verdict for p256_point.c's ladder in 42 minutes
// (proof/run.sh). Over these stubs the whole multiplication is one formula,
// so every index its loop builds from a counter is proven in bounds on the
// shipped loop, at every trip.
//
// Every output is stored through the coordinate's own type, never a byte
// fill of a point (docs/proofs.md).
#ifndef CH_PROOF_P256_WIDE_POINT_STUBS_H
#define CH_PROOF_P256_WIDE_POINT_STUBS_H

#include "harness.h"

#include "p256_wide_point.h"

uint64_t nondet_u64(void);

static void havoc_wide_point(p256_wide_point *o) {
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof *o), "wide point output writable");
    for (size_t i = 0; i < P256_WIDE_FE_LIMBS; i++) {
        o->x.limb[i] = nondet_u64();
        o->y.limb[i] = nondet_u64();
        o->z.limb[i] = nondet_u64();
    }
}

void p256_wide_point_from_portable(p256_wide_point *o, const p256_point *a) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a), "from_portable: point readable");
    havoc_wide_point(o);
}

void p256_wide_point_to_portable(p256_point *o, const p256_wide_point *a) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a), "to_portable: point readable");
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof *o), "to_portable: output writable");
    for (size_t i = 0; i < P256_FE_LIMBS; i++) {
        o->x.limb[i] = nondet_u32();
        o->y.limb[i] = nondet_u32();
        o->z.limb[i] = nondet_u32();
    }
}

void p256_wide_point_add(p256_wide_point *o, const p256_wide_point *a, const p256_wide_point *b) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a), "add: first point readable");
    __CPROVER_assert(__CPROVER_r_ok(b, sizeof *b), "add: second point readable");
    havoc_wide_point(o);
}

#endif
