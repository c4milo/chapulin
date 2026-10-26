// The Wycheproof ML-DSA-87 suites (docs/decisions.md 154). The verify
// suite's cases each go to mldsa87_verify whole, a key or a signature of
// the wrong length and a context over 255 bytes among them. The valid
// signatures of the two signing suites must verify: by the message and
// context, or by mu through mldsa87_challenge where a case has mu alone.
// The includer defines fail(), check_verdict() and COUNT, and includes
// mldsa.h and the vectors header first.
#ifndef CH_TEST_WYCHEPROOF_MLDSA_H
#define CH_TEST_WYCHEPROOF_MLDSA_H

static void run_mldsa_verify(void) {
    size_t accepted = 0;
    for (size_t i = 0; i < COUNT(wp_mldsa_verify); i++) {
        const uint8_t *pk = wp_mldsa_verify_data + wp_mldsa_verify[i].off;
        const uint8_t *msg = pk + wp_mldsa_verify[i].pk_len;
        const uint8_t *ctx = msg + wp_mldsa_verify[i].msg_len;
        const uint8_t *sig = ctx + wp_mldsa_verify[i].ctx_len;
        int ok = mldsa87_verify(pk, wp_mldsa_verify[i].pk_len, msg, wp_mldsa_verify[i].msg_len, ctx,
                                wp_mldsa_verify[i].ctx_len, sig, wp_mldsa_verify[i].sig_len);
        check_verdict("mldsa-87-verify", wp_mldsa_verify[i].tc, ok, wp_mldsa_verify[i].valid);
        accepted += (size_t)(ok == 1);
    }
    printf("wycheproof mldsa-87 verify: %zu cases, %zu valid\n", COUNT(wp_mldsa_verify), accepted);
}

static void run_mldsa_signatures(void) {
    for (size_t i = 0; i < COUNT(wp_mldsa_sign); i++) {
        const uint8_t *pk = wp_mldsa_sign_data + wp_mldsa_sign[i].off;
        const uint8_t *msg = pk + MLDSA87_PK_LEN;
        const uint8_t *ctx = msg + wp_mldsa_sign[i].msg_len;
        const uint8_t *sig = ctx + wp_mldsa_sign[i].ctx_len;
        int ok;
        if (wp_mldsa_sign[i].by_mu) {
            uint8_t c_tilde[MLDSA87_CTILDE_LEN];
            ok = mldsa87_challenge(c_tilde, pk, msg, sig) == 1 &&
                 memcmp(c_tilde, sig, MLDSA87_CTILDE_LEN) == 0;
        } else {
            ok = mldsa87_verify(pk, MLDSA87_PK_LEN, msg, wp_mldsa_sign[i].msg_len, ctx,
                                wp_mldsa_sign[i].ctx_len, sig, MLDSA87_SIG_LEN);
        }
        check_verdict("mldsa-87-signatures", wp_mldsa_sign[i].tc, ok, 1);
    }
    printf("wycheproof mldsa-87 signatures: %zu cases, %d skipped (a signer must refuse them)\n",
           COUNT(wp_mldsa_sign), WP_MLDSA_SIGN_SKIPPED);
}

#endif
