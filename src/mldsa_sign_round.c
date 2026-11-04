// One round of ML-DSA-87's rejection loop (FIPS 204 Algorithm 7).
// Contract in mldsa_sign_round.h.
#include "mldsa_sign_round.h"

#include "ct.h"

int mlds_sign_round(mlds_round *st, uint8_t sig[MLDSA87_SIG_LEN], const uint8_t *sk,
                    const uint8_t mu[MLDSA_MU_LEN], const uint8_t rho2[64], unsigned kappa) {
    if (!mlds_commit(st, sk, mu, rho2, kappa)) {
        return -1;
    }
    for (unsigned i = 0; i < MLD_K; i++) {
        for (unsigned b = 0; b < MLD_N / 8; b++) {
            st->hints[i][b] = 0;
        }
    }
    uint32_t count = 0;
    uint32_t reject = mlds_response(st, sk, rho2, kappa);
    for (unsigned i = 0; i < MLD_K; i++) {
        reject |= mlds_hint_row(st, sk, i, &count);
    }
    reject |= (MLD_OMEGA - count) >> 31;
    // The round's verdict: the count of rounds is public (mldsa_signer.h).
    CT_DECLASSIFY(&reject, sizeof reject);
    if (reject != 0) {
        return 0;
    }
    mlds_encode(sig, st);
    return 1;
}
