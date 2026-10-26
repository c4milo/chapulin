// Holds the test-only ML-DSA-87 signer, test/mldsa_sign.c, to Wycheproof's
// seeded signing suite (docs/decisions.md 157). For each valid case it
// expands the seed and requires the suite's public key, signs the message
// and context, or mu, with the case's rnd, and requires the suite's
// signature byte for byte, and mldsa87_verify must accept it. The suite's
// deterministic, hedged, many-step and boundary cases are all among them,
// so the rejection loop's edges run here. The mock servers of the
// PROFILE=cnsa2 tests sign with this signer, so their signatures are FIPS
// 204's. It reads bin/wycheproof_mldsa_sign_vectors.h, which
// test/gen_wycheproof.py writes.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mldsa.h"
#include "mldsa_sign.h"
#include "wycheproof_mldsa_sign_vectors.h"

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

int main(void) {
    static mldsa_test_key key;
    int failures = 0;
    for (size_t i = 0; i < COUNT(wp_mldsa_seed); i++) {
        const uint8_t *seed = wp_mldsa_seed_data + wp_mldsa_seed[i].off;
        const uint8_t *pk = seed + 32;
        const uint8_t *rnd = pk + MLDSA87_PK_LEN;
        const uint8_t *msg = rnd + 32;
        const uint8_t *ctx = msg + wp_mldsa_seed[i].msg_len;
        const uint8_t *want = ctx + wp_mldsa_seed[i].ctx_len;
        mldsa_test_keygen(&key, seed);
        uint8_t sig[MLDSA87_SIG_LEN];
        int signed_ok = wp_mldsa_seed[i].by_mu
                            ? mldsa_test_sign_mu(&key, msg, rnd, sig)
                            : mldsa_test_sign(&key, msg, wp_mldsa_seed[i].msg_len, ctx,
                                              wp_mldsa_seed[i].ctx_len, rnd, sig);
        int ok = memcmp(key.pk, pk, MLDSA87_PK_LEN) == 0 && signed_ok &&
                 memcmp(sig, want, MLDSA87_SIG_LEN) == 0;
        if (ok && !wp_mldsa_seed[i].by_mu) {
            ok = mldsa87_verify(key.pk, MLDSA87_PK_LEN, msg, wp_mldsa_seed[i].msg_len, ctx,
                                wp_mldsa_seed[i].ctx_len, sig, MLDSA87_SIG_LEN);
        }
        if (!ok) {
            (void)fprintf(stderr, "FAIL mldsa-87 signer tc%u\n", (unsigned)wp_mldsa_seed[i].tc);
            failures++;
        }
    }
    if (failures > 0 || COUNT(wp_mldsa_seed) != WP_MLDSA_SEED_CASES) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)printf("wycheproof mldsa-87 signer: %zu cases, all keys and signatures match (commit "
                 "%.12s)\n",
                 COUNT(wp_mldsa_seed), WYCHEPROOF_COMMIT);
    return 0;
}
