// Proves: one step of each masked rejection sampler of mldsa_sign_pack.c,
// RejBoundedPoly's keep_half_byte and SampleInBall's ball_step, is
// memory-safe and UB-free with the signed-overflow check on, from every
// state the sampler's loop can be in, and the step keeps the state's
// invariant:
//  - keep_half_byte, for every half-byte z, every count from 0 to 256 and
//    every polynomial: the count grows by at most 1 and stays at most 256,
//    it grows exactly when z is under 15 and the count was under 256, and
//    each coefficient is the one before or the step's value, which is in
//    [-2, 2];
//  - ball_step, for every position j from the stream, every i from 196
//    to 256 and every polynomial and sign word: i grows by at most 1 and
//    stays at most 256, and each coefficient is the one before, the one at
//    j, or +1 or -1.
// So by induction over the loop each sampler's output is in range: s1 and
// s2 coefficients in [-2, 2], c's in {-1, 0, 1}, from the zeros each loop
// starts with.
//
// The two loops that drive the steps run MLDS_ETA_STREAM_BYTES and
// MLD_BALL_BYTES - 8 steps over constant indexes into their streams. A
// formula of the whole loop holds 962 or 264 steps of a 256-position scan,
// and cbmc passed 7.8 GB in symbolic execution on it after 1,108 s on an
// M1 Pro (docs/decisions.md 159). bin/mldsa_signer_test holds
// mlds_sample_in_ball to the verifier's sampler value for value, and the
// keys bin/wycheproof_mldsa_library_test expands hold mlds_sample_eta to
// FIPS 204.
#include "harness.h"

#include "mldsa_sign_pack.c"

int32_t nondet_i32(void);

static void havoc_poly(mld_poly *p) {
    for (unsigned n = 0; n < MLD_N; n++) {
        p->coeffs[n] = nondet_i32();
    }
}

static void eta_step(void) {
    mld_poly p;
    mld_poly before;
    havoc_poly(&p);
    before = p;
    uint32_t count = nondet_u32();
    __CPROVER_assume(count <= MLD_N);
    uint32_t z = nondet_u32() & 15U;
    uint32_t start = count;
    keep_half_byte(&p, &count, z);
    __CPROVER_assert(count <= MLD_N, "keep_half_byte: the count stays at most 256");
    __CPROVER_assert(count == start + ((z < 15 && start < MLD_N) ? 1U : 0U),
                     "keep_half_byte: one more exactly for a kept half-byte");
    unsigned n = nondet_u32() % MLD_N;
    __CPROVER_assert(p.coeffs[n] == before.coeffs[n] ||
                         (n == start && p.coeffs[n] >= -MLDS_ETA && p.coeffs[n] <= MLDS_ETA),
                     "keep_half_byte: one coefficient takes a value in [-2, 2]");
}

static void ball(void) {
    mld_poly c;
    mld_poly before;
    havoc_poly(&c);
    before = c;
    uint32_t i = nondet_u32();
    __CPROVER_assume(i >= MLD_N - MLD_TAU && i <= MLD_N);
    uint32_t j = nondet_u8();
    sign_bits signs = {nondet_u32(), nondet_u32()};
    uint32_t start = i;
    ball_step(&c, &i, j, &signs);
    __CPROVER_assert(i <= MLD_N && i - start <= 1, "ball_step: i grows by at most 1");
    unsigned n = nondet_u32() % MLD_N;
    __CPROVER_assert(c.coeffs[n] == before.coeffs[n] || c.coeffs[n] == before.coeffs[j] ||
                         c.coeffs[n] == 1 || c.coeffs[n] == -1,
                     "ball_step: a coefficient is kept, moved, or a sign");
}

int main(void) {
    eta_step();
    ball();
    return 0;
}
