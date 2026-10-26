// The contracts of the layers one round of ML-DSA-87's rejection loop
// calls, for the harnesses of mldsa_sign_steps.c: mldsa_sign_commit,
// mldsa_sign_response and mldsa_sign_hint_row. Each stub asserts what its
// function requires and havocs its outputs to any value its contract
// allows, and each verdict to either answer:
//  - the polynomial layer, which mldsa_sign_poly and mldsa_sign_ntt prove:
//    a product's coefficients centered, a frozen row's in [0, q);
//  - the encodings and samplers, which mldsa_sign_pack and
//    mldsa_sign_samplers prove: y in (-gamma1, gamma1], c in {-1, 0, 1},
//    an unpacked polynomial in (offset - 2^bits, offset];
//  - the verifier's sampler of A and the SHAKE sponge, to their pointer
//    contracts, as in mldsa_poly_harness.c;
//  - the coefficient functions the steps call, which
//    mldsa_sign_coefficient proves, with their domains asserted: every
//    value decomposed is in [0, q), and every value checked against a
//    norm bound is under 2^30.
//
// The includer includes this header before mldsa_sign_steps.c. This
// header includes mldsa_sign_pack.h and mldsa_sign_poly.h first, so the
// defines rename the coefficient calls in mldsa_sign_steps.c alone, and
// the headers' include guards keep its own includes from reading the real
// bodies again.
#ifndef CH_PROOF_MLDSA_SIGN_STEP_STUBS_H
#define CH_PROOF_MLDSA_SIGN_STEP_STUBS_H

#include "harness.h"
#include "mldsa_sign_pack.h"
#include "mldsa_sign_poly.h"
#include "sha3.h"

int32_t nondet_i32(void);

static int32_t stub_round_freeze(int32_t a) {
    (void)a;
    int32_t r = (int32_t)(nondet_u32() >> 9);
    __CPROVER_assume(r < MLD_Q);
    return r;
}

static int32_t stub_round_decompose(int32_t r, int32_t *r0) {
    __CPROVER_assert(r >= 0 && r < MLD_Q, "mlds_decompose: r in [0, q)");
    int32_t low = (int32_t)(nondet_u32() << 13) >> 13;
    __CPROVER_assume(low >= -MLD_GAMMA2 && low <= MLD_GAMMA2);
    *r0 = low;
    return (int32_t)(nondet_u32() & 15U);
}

static uint32_t stub_round_at_least(int32_t a, int32_t bound) {
    __CPROVER_assert(a < (1 << 30) && a > -(1 << 30), "mlds_at_least: |a| under 2^30");
    __CPROVER_assert(bound >= 1 && bound <= (1 << 30), "mlds_at_least: a bound it takes");
    return nondet_u32() & 1U;
}

#define mlds_freeze stub_round_freeze
#define mlds_decompose stub_round_decompose
#define mlds_at_least stub_round_at_least

static void havoc_poly(mld_poly *p) {
    __CPROVER_assert(__CPROVER_w_ok(p, sizeof *p), "poly output writable");
    for (unsigned i = 0; i < MLD_N; i++) {
        p->coeffs[i] = nondet_i32();
    }
}

// Coefficients in [lo, hi], each a nondet word under an assumption.
static void havoc_range(mld_poly *p, int32_t lo, int32_t hi) {
    __CPROVER_assert(__CPROVER_w_ok(p, sizeof *p), "poly output writable");
    for (unsigned i = 0; i < MLD_N; i++) {
        int32_t v = nondet_i32();
        __CPROVER_assume(v >= lo && v <= hi);
        p->coeffs[i] = v;
    }
}

static void assert_poly_readable(const mld_poly *p) {
    __CPROVER_assert(__CPROVER_r_ok(p, sizeof *p), "poly input readable");
}

static uint32_t nondet_bit(void) {
    return nondet_u32() & 1U;
}

void mlds_poly_ntt(mld_poly *p) {
    havoc_poly(p);
}

void mlds_poly_pointwise(mld_poly *r, const mld_poly *a, const mld_poly *b) {
    assert_poly_readable(a);
    assert_poly_readable(b);
    havoc_poly(r);
}

void mlds_poly_pointwise_acc(mld_poly *acc, const mld_poly *a, const mld_poly *b) {
    assert_poly_readable(acc);
    assert_poly_readable(a);
    assert_poly_readable(b);
    havoc_poly(acc);
}

void mlds_poly_product(mld_poly *r, const mld_poly *a_hat, const mld_poly *b_hat) {
    assert_poly_readable(a_hat);
    assert_poly_readable(b_hat);
    havoc_range(r, -(MLD_Q - 1) / 2, (MLD_Q - 1) / 2);
}

void mlds_poly_invntt_freeze(mld_poly *p) {
    havoc_range(p, 0, MLD_Q - 1);
}

void mlds_pack(uint8_t *out, const mld_poly *p, unsigned bits, int32_t offset) {
    (void)offset;
    assert_poly_readable(p);
    __CPROVER_assert(bits == 3 || bits == 4 || bits == 10 || bits == 13 || bits == 20,
                     "mlds_pack: a width the signer packs");
    __CPROVER_assert(__CPROVER_w_ok(out, (size_t)32 * bits), "mlds_pack: output writable");
    __CPROVER_havoc_slice(out, (size_t)32 * bits);
}

void mlds_unpack(mld_poly *p, const uint8_t *in, unsigned bits, int32_t offset) {
    __CPROVER_assert(bits == 3 || bits == 13, "mlds_unpack: s2 or t0");
    __CPROVER_assert(__CPROVER_r_ok(in, (size_t)32 * bits), "mlds_unpack: input readable");
    havoc_range(p, offset - (1 << bits) + 1, offset);
}

uint32_t mlds_unpack_eta(mld_poly *p, const uint8_t in[MLDS_ETA_BYTES]) {
    __CPROVER_assert(__CPROVER_r_ok(in, MLDS_ETA_BYTES), "mlds_unpack_eta: input readable");
    havoc_range(p, -5, 2);
    return nondet_bit();
}

uint32_t mlds_sample_eta(mld_poly *p, const uint8_t rho_prime[64], uint16_t nonce) {
    __CPROVER_assert(__CPROVER_r_ok(rho_prime, 64), "mlds_sample_eta: rho' readable");
    __CPROVER_assert(nonce < MLD_L + MLD_K, "mlds_sample_eta: the nonce of s1 or s2");
    havoc_range(p, -MLDS_ETA, MLDS_ETA);
    return nondet_bit();
}

void mlds_expand_mask(mld_poly *p, const uint8_t rho2[64], uint16_t nonce) {
    (void)nonce;
    __CPROVER_assert(__CPROVER_r_ok(rho2, 64), "mlds_expand_mask: rho'' readable");
    havoc_range(p, -MLD_GAMMA1 + 1, MLD_GAMMA1);
}

uint32_t mlds_sample_in_ball(mld_poly *c, const uint8_t c_tilde[64]) {
    __CPROVER_assert(__CPROVER_r_ok(c_tilde, 64), "mlds_sample_in_ball: c-tilde readable");
    havoc_range(c, -1, 1);
    return nondet_bit();
}

int mld_sample_ntt(mld_poly *p, const uint8_t rho[MLD_RHO_BYTES], uint8_t s, uint8_t r) {
    __CPROVER_assert(__CPROVER_r_ok(rho, MLD_RHO_BYTES), "rho readable");
    __CPROVER_assert(s < MLD_L && r < MLD_K, "A's entry is inside the matrix");
    havoc_poly(p);
    return (int)nondet_bit();
}

void shake256_init(shake *s) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "shake256_init: ctx writable");
    fill_nondet((uint8_t *)s, sizeof *s);
}

void shake_absorb(shake *s, const uint8_t *in, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "shake_absorb: ctx writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "shake_absorb: input readable");
}

void shake_squeeze(shake *s, uint8_t *out, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "shake_squeeze: ctx writable");
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(out, n), "shake_squeeze: output writable");
    fill_nondet(out, n);
}

#endif
