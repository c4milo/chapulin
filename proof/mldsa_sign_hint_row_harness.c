// Proves: mlds_hint_row, the low-bits check, the ct0 check and the hints
// of one row of one round of ML-DSA-87's rejection loop (FIPS 204
// Algorithm 7, steps 21 to 28), is memory-safe and UB-free with the
// signed-overflow check on, for the last row, every secret key, every
// NTT(c) and every w in [0, q), the domain mlds_commit leaves. Every
// value it decomposes is in [0, q), every value it checks is under 2^30,
// it sets bits of row i alone, and it adds at most 256 to the count. The
// layers are stubbed to their contracts (proof/mldsa_sign_step_stubs.h).
#include "harness.h"
#include "mldsa_sign_pack.h"
#include "mldsa_sign_poly.h"
#include "mldsa_sign_step_stubs.h"
#include "sha3.h"

#include "mldsa_sign_steps.c"

#ifndef HINT_ROW
#define HINT_ROW (MLD_K - 1)
#endif

static mlds_round st;
static uint8_t sk[MLDSA87_SK_LEN];

int main(void) {
    __CPROVER_havoc_object(sk);
    __CPROVER_havoc_object(&st);
    // The last row: its s2 and t0 polynomials lie furthest into sk.
    // HINT_ROW selects another row for a second formula.
    unsigned i = HINT_ROW;
    for (unsigned n = 0; n < MLD_N; n++) {
        __CPROVER_assume(st.w[i].coeffs[n] >= 0 && st.w[i].coeffs[n] < MLD_Q);
    }
    unsigned other = nondet_u32();
    __CPROVER_assume(other < MLD_K && other != i);
    unsigned at = nondet_u32() % (MLD_N / 8);
    uint8_t before = st.hints[other][at];
    uint32_t count = nondet_u32();
    __CPROVER_assume(count <= MLD_K * MLD_N);
    uint32_t start = count;
    uint32_t reject = mlds_hint_row(&st, sk, i, &count);
    __CPROVER_assert(reject <= 1, "mlds_hint_row: a verdict of 0 or 1");
    __CPROVER_assert(count >= start && count - start <= MLD_N, "mlds_hint_row: at most 256 hints");
    __CPROVER_assert(st.hints[other][at] == before, "mlds_hint_row: no bit of another row");
    return 0;
}
