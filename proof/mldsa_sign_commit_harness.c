// Proves: mlds_commit, the commitment and the challenge of one round of
// ML-DSA-87's rejection loop (FIPS 204 Algorithm 7, steps 11 to 17), is
// memory-safe and UB-free with the signed-overflow check on, over every
// secret key, mu, rho'' and kappa the loop passes. Every value it
// decomposes is in [0, q): w's rows come frozen from mlds_matrix_row, the
// real one, over the contracts of the products. Each entry of A it asks
// for is inside the matrix. mlds_key_in_range reads the 15 polynomials of
// s1 and s2 inside sk. The layers are stubbed to their contracts
// (proof/mldsa_sign_step_stubs.h).
#include "harness.h"
#include "mldsa_sign_pack.h"
#include "mldsa_sign_poly.h"
#include "mldsa_sign_step_stubs.h"
#include "sha3.h"

#include "mldsa_sign_steps.c"

static mlds_round st;
static uint8_t sk[MLDSA87_SK_LEN];

int main(void) {
    uint8_t mu[MLDSA_MU_LEN];
    uint8_t rho2[64];
    __CPROVER_havoc_object(sk);
    __CPROVER_havoc_object(mu);
    __CPROVER_havoc_object(rho2);
    (void)mlds_key_in_range(&st, sk);
    unsigned kappa = nondet_u32();
    __CPROVER_assume(kappa % MLD_L == 0 && kappa < MLDSA87_SIGN_ROUNDS * MLD_L);
    int ok = mlds_commit(&st, sk, mu, rho2, kappa);
    __CPROVER_assert(ok == 0 || ok == 1, "mlds_commit: 0 or 1");
    return 0;
}
