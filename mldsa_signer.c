// ML-DSA-87 key generation and signing (FIPS 204 Algorithms 2, 6 and 7):
// the hashes, the order of key generation and the rejection loop.
// Contract in mldsa_signer.h. mldsa_sign_round.c holds one round of the
// loop, mldsa_sign_steps.c the round's steps and a row of key generation,
// mldsa_sign_poly.c the ring arithmetic and mldsa_sign_pack.c the
// encodings and the samplers.
#include "mldsa_signer.h"

#include "ch_assert.h"
#include "ct.h"
#include "mldsa_poly.h"
#include "mldsa_sign_pack.h"
#include "mldsa_sign_poly.h"
#include "mldsa_sign_round.h"
#include "sha3.h"

_Static_assert(MLDSA87_SIGN_ROUNDS *MLD_L + MLD_L <= 0x10000, "kappa fits ExpandMask's 16 bits");

int mldsa87_keygen(uint8_t sk[MLDSA87_SK_LEN], uint8_t pk[MLDSA87_PK_LEN],
                   const uint8_t seed[MLDSA87_SEED_LEN]) {
    CH_ASSERT(sk != NULL && pk != NULL && seed != NULL);
    mlds_keygen_state st;
    const uint8_t dims[2] = {MLD_K, MLD_L};
    shake h;
    shake256_init(&h);
    shake_absorb(&h, seed, MLDSA87_SEED_LEN);
    shake_absorb(&h, dims, sizeof dims);
    shake_squeeze(&h, st.seeds, sizeof st.seeds);
    for (unsigned b = 0; b < MLD_RHO_BYTES; b++) {
        sk[b] = st.seeds[b];
        pk[b] = st.seeds[b];
        sk[MLDS_SK_KEY_AT + b] = st.seeds[96 + b];
    }
    uint32_t ok = 1;
    for (unsigned r = 0; r < MLD_L; r++) {
        ok &= mlds_sample_eta(&st.s1_hat[r], st.seeds + 32, (uint16_t)r);
        mlds_pack(sk + MLDS_SK_S1_AT + (size_t)r * MLDS_ETA_BYTES, &st.s1_hat[r], 3, MLDS_ETA);
        mlds_poly_ntt(&st.s1_hat[r]);
    }
    for (unsigned i = 0; i < MLD_K; i++) {
        ok &= mlds_keygen_row(&st, sk, pk, i);
    }
    shake256_init(&h);
    shake_absorb(&h, pk, MLDSA87_PK_LEN);
    shake_squeeze(&h, sk + MLDS_SK_TR_AT, 64);
    ct_wipe(&h, sizeof h);
    ct_wipe(&st, sizeof st);
    // A sampler at its bound, a verdict that FIPS 204 Appendix C treats as
    // public.
    CT_DECLASSIFY(&ok, sizeof ok);
    if (ok != 1) {
        ct_wipe(sk, MLDSA87_SK_LEN);
        ct_wipe(pk, MLDSA87_PK_LEN);
        return 0;
    }
    return 1;
}

// FIPS 204 Algorithm 7, ML-DSA.Sign_internal, from mu: the rejection loop,
// at most MLDSA87_SIGN_ROUNDS rounds. Returns the rounds the signature
// took, or 0 with sig unwritten. Every intermediate value is wiped on
// every path, the bound's paths among them (FIPS 204 Appendix C).
//
// The round's state is this frame's, and the compiler may not inline the
// function into its caller. So the frame is gone when the caller verifies
// the signature, and the stack holds the signer's frame or the
// verifier's, never both (lint-stack).
static __attribute__((noinline)) unsigned sign_rounds(uint8_t sig[MLDSA87_SIG_LEN],
                                                      const uint8_t sk[MLDSA87_SK_LEN],
                                                      const uint8_t mu[MLDSA_MU_LEN],
                                                      const uint8_t rnd[MLDSA87_RND_LEN]) {
    mlds_round st;
    uint8_t rho2[64];
    shake h;
    shake256_init(&h);
    shake_absorb(&h, sk + MLDS_SK_KEY_AT, 32);
    shake_absorb(&h, rnd, MLDSA87_RND_LEN);
    shake_absorb(&h, mu, MLDSA_MU_LEN);
    shake_squeeze(&h, rho2, sizeof rho2);
    ct_wipe(&h, sizeof h);
    uint32_t in_range = mlds_key_in_range(&st, sk);
    CT_DECLASSIFY(&in_range, sizeof in_range);
    unsigned rounds = 0;
    for (unsigned round = 0; in_range == 1 && round < MLDSA87_SIGN_ROUNDS; round++) {
        int passed = mlds_sign_round(&st, sig, sk, mu, rho2, round * MLD_L);
        if (passed != 0) {
            rounds = passed == 1 ? round + 1 : 0;
            break;
        }
    }
    ct_wipe(&st, sizeof st);
    ct_wipe(rho2, sizeof rho2);
    return rounds;
}

// Whether rnd holds a byte other than 0. The answer is the draw's, which
// a source that wrote nothing gives, and it ends the call (INV-4).
static int rnd_drawn(const uint8_t rnd[MLDSA87_RND_LEN]) {
    uint32_t any = 0;
    for (unsigned b = 0; b < MLDSA87_RND_LEN; b++) {
        any |= rnd[b];
    }
    CT_DECLASSIFY(&any, sizeof any);
    return any != 0;
}

// mldsa87_sign after its refusal of zero rnd: mu (FIPS 204 Algorithm 7,
// step 6, over Algorithm 2's M'), the loop, and the check under pk.
static unsigned sign_checked(uint8_t sig[MLDSA87_SIG_LEN], const uint8_t *sk, size_t sk_len,
                             const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len,
                             const uint8_t *ctx, size_t ctx_len,
                             const uint8_t rnd[MLDSA87_RND_LEN]) {
    if (sk_len != MLDSA87_SK_LEN || pk_len != MLDSA87_PK_LEN || ctx_len > MLDSA_CONTEXT_MAX) {
        ct_wipe(sig, MLDSA87_SIG_LEN);
        return 0;
    }
    const uint8_t prefix[2] = {0, (uint8_t)ctx_len};
    uint8_t mu[MLDSA_MU_LEN];
    shake h;
    shake256_init(&h);
    shake_absorb(&h, sk + MLDS_SK_TR_AT, 64);
    shake_absorb(&h, prefix, sizeof prefix);
    shake_absorb(&h, ctx, ctx_len);
    shake_absorb(&h, msg, msg_len);
    shake_squeeze(&h, mu, sizeof mu);
    unsigned rounds = sign_rounds(sig, sk, mu, rnd);
    if (rounds == 0 ||
        !mldsa87_verify(pk, pk_len, msg, msg_len, ctx, ctx_len, sig, MLDSA87_SIG_LEN)) {
        ct_wipe(sig, MLDSA87_SIG_LEN);
        return 0;
    }
    return rounds;
}

int mldsa87_sign(uint8_t sig[MLDSA87_SIG_LEN], const uint8_t *sk, size_t sk_len, const uint8_t *pk,
                 size_t pk_len, const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
                 size_t ctx_len, const uint8_t rnd[MLDSA87_RND_LEN]) {
    CH_ASSERT(sig != NULL && sk != NULL && pk != NULL && rnd != NULL);
    CH_ASSERT(msg != NULL || msg_len == 0);
    CH_ASSERT(ctx != NULL || ctx_len == 0);
    CH_ASSERT(rnd_drawn(rnd));
    return sign_checked(sig, sk, sk_len, pk, pk_len, msg, msg_len, ctx, ctx_len, rnd) != 0;
}

#ifdef CH_MLDSA_SIGN_TEST
int mldsa87_sign_any_rnd(uint8_t sig[MLDSA87_SIG_LEN], const uint8_t *sk, size_t sk_len,
                         const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len,
                         const uint8_t *ctx, size_t ctx_len, const uint8_t rnd[MLDSA87_RND_LEN]) {
    return sign_checked(sig, sk, sk_len, pk, pk_len, msg, msg_len, ctx, ctx_len, rnd) != 0;
}

unsigned mldsa87_sign_mu(uint8_t sig[MLDSA87_SIG_LEN], const uint8_t sk[MLDSA87_SK_LEN],
                         const uint8_t pk[MLDSA87_PK_LEN], const uint8_t mu[MLDSA_MU_LEN],
                         const uint8_t rnd[MLDSA87_RND_LEN]) {
    unsigned rounds = sign_rounds(sig, sk, mu, rnd);
    uint8_t c_tilde[MLDSA87_CTILDE_LEN];
    if (rounds == 0 || !mldsa87_challenge(c_tilde, pk, mu, sig) ||
        ct_memeq(c_tilde, sig, MLDSA87_CTILDE_LEN) != 1) {
        ct_wipe(sig, MLDSA87_SIG_LEN);
        return 0;
    }
    return rounds;
}
#endif
