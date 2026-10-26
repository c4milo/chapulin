// The contracts of mldsa_sign_poly.h's coefficient functions, for the
// harnesses that prove the loops over them: mldsa_sign_ntt and
// mldsa_sign_poly. Each stub asserts what its function requires and
// returns any value its function's bound allows.
// proof/mldsa_sign_coefficient_harness.c proves each function meets that
// bound on every input, on both multiplies.
//
// The includer includes harness.h and mldsa_sign_poly.h first, then this
// header, then mldsa_sign_poly.c. The defines below rename the calls in
// mldsa_sign_poly.c, and mldsa_sign_poly.h's include guard keeps that
// file's own include from reading the real bodies again (docs/proofs.md,
// "When a formula will not converge", step 4).
//
// The bounds are proof/mldsa_stubs.h's: every reduced value and every
// product is in [-2^23, 2^23), a sign extension of 24 bits. mlds_freeze's
// contract is [0, q) and mlds_center's [-(q - 1) / 2, (q - 1) / 2], each
// written as the low 23 bits of a nondet word under an assumption.
#ifndef CH_PROOF_MLDSA_SIGN_STUBS_H
#define CH_PROOF_MLDSA_SIGN_STUBS_H

#include "harness.h"
#include "mldsa_sign_poly.h"

static int32_t nondet_sign_coefficient(void) {
    return (int32_t)(nondet_u32() << 8) >> 8;
}

static int32_t stub_sign_reduce32(int32_t a) {
    (void)a;
    return nondet_sign_coefficient();
}

static int32_t stub_sign_mul_zeta(int32_t zeta, int32_t a) {
    (void)a;
    __CPROVER_assert(zeta <= (MLD_Q - 1) / 2 && zeta >= -(MLD_Q - 1) / 2,
                     "mlds_mul_zeta: the twiddle is at most (q - 1) / 2");
    return nondet_sign_coefficient();
}

static int32_t stub_sign_mul_reduced(int32_t a, int32_t b) {
    (void)a;
    (void)b;
    return nondet_sign_coefficient();
}

static int32_t stub_sign_freeze(int32_t a) {
    (void)a;
    int32_t r = (int32_t)(nondet_u32() >> 9);
    __CPROVER_assume(r < MLD_Q);
    return r;
}

static int32_t stub_sign_center(int32_t a) {
    (void)a;
    int32_t r = (int32_t)(nondet_u32() << 9) >> 9;
    __CPROVER_assume(r >= -(MLD_Q - 1) / 2 && r <= (MLD_Q - 1) / 2);
    return r;
}

#define mlds_reduce32 stub_sign_reduce32
#define mlds_mul_zeta stub_sign_mul_zeta
#define mlds_mul_reduced stub_sign_mul_reduced
#define mlds_freeze stub_sign_freeze
#define mlds_center stub_sign_center

#endif
