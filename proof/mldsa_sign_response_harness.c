// Proves: mlds_response, z = y + c s1 of one round of ML-DSA-87's
// rejection loop (FIPS 204 Algorithm 7, steps 18 to 20 and 23), is
// memory-safe and UB-free with the signed-overflow check on, over every
// secret key, rho'' and kappa the loop passes and every NTT(c). Each sum
// of y and c s1 fits int32_t, and every coefficient of z it checks is under
// 2^30. The layers are stubbed to their contracts
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
    uint8_t rho2[64];
    __CPROVER_havoc_object(sk);
    __CPROVER_havoc_object(rho2);
    __CPROVER_havoc_object(&st);
    unsigned kappa = nondet_u32();
    __CPROVER_assume(kappa % MLD_L == 0 && kappa < MLDSA87_SIGN_ROUNDS * MLD_L);
    uint32_t reject = mlds_response(&st, sk, rho2, kappa);
    __CPROVER_assert(reject <= 1, "mlds_response: a verdict of 0 or 1");
    return 0;
}
