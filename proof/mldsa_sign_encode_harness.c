// Proves: mlds_encode, sigEncode of a round that passed (FIPS 204
// Algorithm 26), is memory-safe and UB-free with the signed-overflow check
// on, for every round state: every hint bit set or clear, every c-tilde
// and every z. It writes the 4,627 bytes of sig and no byte past them,
// and a hint past the omega-th writes no position. mlds_pack is stubbed to
// its pointer contract, which mldsa_sign_pack proves; the rest of
// mldsa_sign_steps.c's layers are stubbed as for the other steps
// (proof/mldsa_sign_step_stubs.h).
#include "harness.h"
#include "mldsa_sign_pack.h"
#include "mldsa_sign_poly.h"
#include "mldsa_sign_step_stubs.h"
#include "sha3.h"

#include "mldsa_sign_steps.c"

static mlds_round st;
static uint8_t sig[MLDSA87_SIG_LEN];

int main(void) {
    __CPROVER_havoc_object(&st);
    mlds_encode(sig, &st);
    return 0;
}
