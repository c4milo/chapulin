// Proves: mlds_keygen_row, a row of t = A s1 + s2 and its two halves in
// ML-DSA-87 key generation (FIPS 204 Algorithm 6, steps 4 to 6), is
// memory-safe and UB-free with the signed-overflow check on, for the last
// row, every seed and every NTT(s1). Every value it splits by Power2Round
// is in [0, q), each entry of A it asks for is inside the matrix, and it
// writes s2's and t0's bytes inside sk and t1's inside pk. The layers are
// stubbed to their contracts (proof/mldsa_sign_step_stubs.h), and
// mldsa_sign_keygen_row0 runs the first row.
#include "harness.h"
#include "mldsa_sign_pack.h"
#include "mldsa_sign_poly.h"
#include "mldsa_sign_step_stubs.h"
#include "sha3.h"

#include "mldsa_sign_steps.c"

#ifndef KEYGEN_ROW
#define KEYGEN_ROW (MLD_K - 1)
#endif

static mlds_keygen_state st;
static uint8_t sk[MLDSA87_SK_LEN];
static uint8_t pk[MLDSA87_PK_LEN];

int main(void) {
    __CPROVER_havoc_object(&st);
    uint32_t ok = mlds_keygen_row(&st, sk, pk, KEYGEN_ROW);
    __CPROVER_assert(ok <= 1, "mlds_keygen_row: a verdict of 0 or 1");
    return 0;
}
