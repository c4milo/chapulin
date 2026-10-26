// One round of ML-DSA-87's rejection loop (FIPS 204 Algorithm 7, steps
// 11 to 32), private to mldsa_signer.c (docs/decisions.md 159). It calls
// the steps of mldsa_sign_steps.c, combines their checks into one verdict
// and encodes the signature of a round that passed. The round sits in a
// file of its own, so that a proof of the loop can replace it with its
// contract.
#ifndef CH_MLDSA_SIGN_ROUND_H
#define CH_MLDSA_SIGN_ROUND_H

#include <stdint.h>

#include "mldsa_sign_steps.h"

// One round of the rejection loop at kappa, for sk, mu and rho''. Returns 1
// when it wrote sig, 0 when a check rejected the round, and -1 when a
// sampler stopped at its bound. sig is written only when it returns 1. st
// holds the round's secrets afterwards, and the caller wipes it.
int mlds_sign_round(mlds_round *st, uint8_t sig[MLDSA87_SIG_LEN], const uint8_t *sk,
                    const uint8_t mu[MLDSA_MU_LEN], const uint8_t rho2[64], unsigned kappa);

#endif
