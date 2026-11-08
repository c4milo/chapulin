// Proves, for a host object (-DCH_CPU_RUNTIME, docs/decisions.md 191),
// with the signed-overflow check on, over every secret key, every cpu
// value and every state:
//  - mlds_expand is memory-safe and UB-free. It reads the 23 polynomials
//    of s1, s2 and t0 inside sk, asks for each entry of A inside the
//    matrix, writes inside ex, and returns 0 or 1;
//  - mlds_response and mlds_hint_row, at the last row, are memory-safe
//    and UB-free when the round reads the key's NTTs from st->ex, with
//    the checks of proof/mldsa_sign_hint_row_harness.c.
// mldsa_sign_expanded_commit proves mlds_commit with the rows of A in
// st->ex; it defines EXPANDED_COMMIT and includes this file.
//
// The layers are stubbed to their contracts (proof/mldsa_sign_step_stubs.h).
// A host object's dispatchers may run mldsa_vector.c's lanes and, on
// x86-64, the four-way sampler of A. CBMC cannot read their intrinsics, so
// each is stubbed below to the contract of the loop it replaces, which
// bin/mldsa_vector_equiv_test and bin/mldsa_avx2_equiv_test hold it to.
#include "harness.h"
#include "mldsa_sign_pack.h"
#include "mldsa_sign_poly.h"
#include "mldsa_sign_step_stubs.h"
#include "sha3.h"

#include "mldsa_sign_steps.c"

#ifndef CH_CPU_RUNTIME
#error "mldsa_sign_expanded proves a host object's signer: -DCH_CPU_RUNTIME"
#endif

#if MLD_VECTOR
void mld_vector_ntt(mld_poly *p) {
    havoc_poly(p);
}

void mld_vector_invntt_tomont(mld_poly *p) {
    havoc_poly(p);
}

void mld_vector_pointwise(mld_poly *r, const mld_poly *a, const mld_poly *b) {
    assert_poly_readable(a);
    assert_poly_readable(b);
    havoc_poly(r);
}

void mld_vector_pointwise_acc(mld_poly *acc, const mld_poly *a, const mld_poly *b) {
    assert_poly_readable(acc);
    assert_poly_readable(a);
    assert_poly_readable(b);
    havoc_poly(acc);
}

void mlds_poly_center(mld_poly *p) {
    havoc_range(p, -(MLD_Q - 1) / 2, (MLD_Q - 1) / 2);
}

void mlds_poly_freeze(mld_poly *p) {
    havoc_range(p, 0, MLD_Q - 1);
}
#endif

#ifdef __x86_64__
int mld_sample_ntt_avx2(mld_poly e[MLD_AVX2_ENTRIES], const uint8_t rho[MLD_RHO_BYTES], unsigned i,
                        unsigned first, unsigned count) {
    __CPROVER_assert(__CPROVER_r_ok(rho, MLD_RHO_BYTES), "mld_sample_ntt_avx2: rho readable");
    __CPROVER_assert(i < MLD_K && count >= 1 && count <= MLD_AVX2_ENTRIES && first + count <= MLD_L,
                     "mld_sample_ntt_avx2: entries inside the row");
    for (unsigned k = 0; k < count; k++) {
        havoc_poly(&e[k]);
    }
    return (int)nondet_bit();
}
#endif

#ifdef CH_KECCAK_INSTRUCTIONS
// The SHAKE calls on the SHA-3 instructions, which an arm64 host object
// that clang compiles holds (sha3.h), to the sponge's pointer contract.
void shake_absorb_hw(shake *s, const uint8_t *in, size_t n) {
    shake_absorb(s, in, n);
}

void shake_squeeze_hw(shake *s, uint8_t *out, size_t n) {
    shake_squeeze(s, out, n);
}
#endif

static mlds_expanded ex;
static mlds_round st;
static uint8_t sk[MLDSA87_SK_LEN];

int main(void) {
    __CPROVER_havoc_object(sk);
    __CPROVER_havoc_object(&ex);
    __CPROVER_havoc_object(&st);
    uint32_t cpu = nondet_u32();
    st.cpu = cpu;
    st.ex = &ex;
#ifdef EXPANDED_COMMIT
    uint8_t mu[MLDSA_MU_LEN];
    uint8_t rho2[64];
    __CPROVER_havoc_object(mu);
    __CPROVER_havoc_object(rho2);
    unsigned kappa = nondet_u32();
    __CPROVER_assume(kappa % MLD_L == 0 && kappa < MLDSA87_SIGN_ROUNDS * MLD_L);
    int ok = mlds_commit(&st, sk, mu, rho2, kappa);
    __CPROVER_assert(ok == 0 || ok == 1, "mlds_commit: 0 or 1");
#else
    uint32_t usable = mlds_expand(&ex, cpu, sk);
    __CPROVER_assert(usable <= 1, "mlds_expand: 0 or 1");
    uint8_t rho2[64];
    __CPROVER_havoc_object(rho2);
    unsigned kappa = nondet_u32();
    __CPROVER_assume(kappa % MLD_L == 0 && kappa < MLDSA87_SIGN_ROUNDS * MLD_L);
    uint32_t reject = mlds_response(&st, sk, rho2, kappa);
    __CPROVER_assert(reject <= 1, "mlds_response: a verdict of 0 or 1");
    unsigned i = MLD_K - 1;
    for (unsigned n = 0; n < MLD_N; n++) {
        __CPROVER_assume(st.w[i].coeffs[n] >= 0 && st.w[i].coeffs[n] < MLD_Q);
    }
    uint32_t count = nondet_u32();
    __CPROVER_assume(count <= MLD_K * MLD_N);
    uint32_t start = count;
    reject = mlds_hint_row(&st, sk, i, &count);
    __CPROVER_assert(reject <= 1, "mlds_hint_row: a verdict of 0 or 1");
    __CPROVER_assert(count >= start && count - start <= MLD_N, "mlds_hint_row: at most 256 hints");
#endif
    return 0;
}
