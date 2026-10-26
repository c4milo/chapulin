// The contracts of mldsa_poly.h's coefficient functions, for the harnesses
// that prove the loops over them: mldsa_ntt and mldsa_poly. Each stub
// asserts what its function requires and returns any value its function's
// bound allows. proof/mldsa_coefficient_harness.c proves each function
// meets that bound on every input.
//
// The includer includes harness.h and mldsa_poly.h first, then this
// header, then mldsa_poly.c. The defines below rename the calls in
// mldsa_poly.c, and mldsa_poly.h's include guard keeps that file's own
// include from reading the real bodies again (docs/proofs.md, "When a
// formula will not converge", step 4).
//
// Each bound is a power of two, written as a sign extension
// (docs/proofs.md): every result is in [-2^23, 2^23). That holds more than
// the functions return: mld_reduce32's results are within 6291200 and the
// two products' under q = 8380417, both below 2^23. The inverse NTT's
// sums still fit in int32_t at this bound: after eight layers a sum holds
// 256 values, at least -2^31 and below 2^31 - 255.
#ifndef CH_PROOF_MLDSA_STUBS_H
#define CH_PROOF_MLDSA_STUBS_H

#include "harness.h"
#include "mldsa_poly.h"

// A value in [-2^23, 2^23): the low 24 bits of a nondet word, sign extended.
static int32_t nondet_coefficient(void) {
    return (int32_t)(nondet_u32() << 8) >> 8;
}

static int32_t stub_reduce32(int32_t a) {
    (void)a;
    return nondet_coefficient();
}

static int32_t stub_mul_zeta(int32_t zeta, int32_t a) {
    (void)a;
    __CPROVER_assert(zeta <= (MLD_Q - 1) / 2 && zeta >= -(MLD_Q - 1) / 2,
                     "mld_mul_zeta: the twiddle is at most (q - 1) / 2");
    return nondet_coefficient();
}

static int32_t stub_mul_reduced(int32_t a, int32_t b) {
    (void)a;
    (void)b;
    return nondet_coefficient();
}

static uint32_t stub_use_hint_coefficient(int32_t w, uint32_t hint) {
    (void)w;
    __CPROVER_assert(hint <= 1, "mld_use_hint_coefficient: the hint is a bit");
    uint32_t r1 = nondet_u32();
    __CPROVER_assume(r1 < 16);
    return r1;
}

#define mld_reduce32 stub_reduce32
#define mld_mul_zeta stub_mul_zeta
#define mld_mul_reduced stub_mul_reduced
#define mld_use_hint_coefficient stub_use_hint_coefficient

#endif
