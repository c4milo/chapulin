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

// mldsa87_keygen under cpu, the session's ch_cfg.cpu or 0, which
// mldsa_sign_poly.h's dispatchers read.
static int keygen(uint32_t cpu, uint8_t sk[MLDSA87_SK_LEN], uint8_t pk[MLDSA87_PK_LEN],
                  const uint8_t seed[MLDSA87_SEED_LEN]) {
    CH_ASSERT(sk != NULL && pk != NULL && seed != NULL);
    mlds_keygen_state st;
    st.cpu = cpu;
    const uint8_t dims[2] = {MLD_K, MLD_L};
    shake h;
    shake256_init(&h);
    mld_absorb(cpu, &h, seed, MLDSA87_SEED_LEN);
    mld_absorb(cpu, &h, dims, sizeof dims);
    mld_squeeze(cpu, &h, st.seeds, sizeof st.seeds);
    for (unsigned b = 0; b < MLD_RHO_BYTES; b++) {
        sk[b] = st.seeds[b];
        pk[b] = st.seeds[b];
        sk[MLDS_SK_KEY_AT + b] = st.seeds[96 + b];
    }
    uint32_t ok = 1;
    for (unsigned r = 0; r < MLD_L; r++) {
        ok &= mlds_sample_eta(cpu, &st.s1_hat[r], st.seeds + 32, (uint16_t)r);
        mlds_pack(sk + MLDS_SK_S1_AT + (size_t)r * MLDS_ETA_BYTES, &st.s1_hat[r], 3, MLDS_ETA);
        mlds_ntt(st.cpu, &st.s1_hat[r]);
    }
    for (unsigned i = 0; i < MLD_K; i++) {
        ok &= mlds_keygen_row(&st, sk, pk, i);
    }
    shake256_init(&h);
    mld_absorb(cpu, &h, pk, MLDSA87_PK_LEN);
    mld_squeeze(cpu, &h, sk + MLDS_SK_TR_AT, 64);
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

int mldsa87_keygen(uint8_t sk[MLDSA87_SK_LEN], uint8_t pk[MLDSA87_PK_LEN],
                   const uint8_t seed[MLDSA87_SEED_LEN]) {
    return keygen(0, sk, pk, seed);
}

#ifdef CH_CPU_RUNTIME
int mldsa87_keygen_cpu(uint32_t cpu, uint8_t sk[MLDSA87_SK_LEN], uint8_t pk[MLDSA87_PK_LEN],
                       const uint8_t seed[MLDSA87_SEED_LEN]) {
    return keygen(cpu, sk, pk, seed);
}
#endif

// rho'' (FIPS 204 Algorithm 7, step 7): SHAKE256(K || rnd || mu).
static void private_seed(uint32_t cpu, uint8_t rho2[64], const uint8_t sk[MLDSA87_SK_LEN],
                         const uint8_t mu[MLDSA_MU_LEN], const uint8_t rnd[MLDSA87_RND_LEN]) {
    shake h;
    shake256_init(&h);
    mld_absorb(cpu, &h, sk + MLDS_SK_KEY_AT, 32);
    mld_absorb(cpu, &h, rnd, MLDSA87_RND_LEN);
    mld_absorb(cpu, &h, mu, MLDSA_MU_LEN);
    mld_squeeze(cpu, &h, rho2, 64);
    ct_wipe(&h, sizeof h);
}

// The rejection loop of FIPS 204 Algorithm 7 over st, at most
// MLDSA87_SIGN_ROUNDS rounds. Returns the rounds the signature took, or 0
// with sig unwritten.
static unsigned rejection_loop(mlds_round *st, uint8_t sig[MLDSA87_SIG_LEN],
                               const uint8_t sk[MLDSA87_SK_LEN], const uint8_t mu[MLDSA_MU_LEN],
                               const uint8_t rho2[64]) {
    for (unsigned round = 0; round < MLDSA87_SIGN_ROUNDS; round++) {
        int passed = mlds_sign_round(st, sig, sk, mu, rho2, round * MLD_L);
        if (passed != 0) {
            return passed == 1 ? round + 1 : 0;
        }
    }
    return 0;
}

#if !defined(CH_CPU_RUNTIME) || defined(CH_MLDSA_SIGN_TEST)
// FIPS 204 Algorithm 7, ML-DSA.Sign_internal, from mu, as a device object
// signs: each round decodes and samples what it needs (docs/decisions.md
// 159). Returns the rounds the signature took, or 0 with sig unwritten.
// Every intermediate value is wiped on every path, the bound's paths among
// them (FIPS 204 Appendix C). A host object signs on sign_rounds_expanded,
// and its test binaries call this frame to compare the two.
//
// The round's state is this frame's, and the compiler may not inline the
// function into its caller. So the frame is gone when the caller verifies
// the signature, and the stack holds the signer's frame or the
// verifier's, never both (lint-stack).
static __attribute__((noinline)) unsigned sign_rounds(uint32_t cpu, uint8_t sig[MLDSA87_SIG_LEN],
                                                      const uint8_t sk[MLDSA87_SK_LEN],
                                                      const uint8_t mu[MLDSA_MU_LEN],
                                                      const uint8_t rnd[MLDSA87_RND_LEN]) {
    mlds_round st;
    st.cpu = cpu;
#ifdef CH_CPU_RUNTIME
    st.ex = NULL;
#endif
    uint8_t rho2[64];
    private_seed(cpu, rho2, sk, mu, rnd);
    uint32_t in_range = mlds_key_in_range(&st, sk);
    CT_DECLASSIFY(&in_range, sizeof in_range);
    unsigned rounds = in_range == 1 ? rejection_loop(&st, sig, sk, mu, rho2) : 0;
    ct_wipe(&st, sizeof st);
    ct_wipe(rho2, sizeof rho2);
    return rounds;
}
#endif

#ifdef CH_CPU_RUNTIME
// sign_rounds as a host object signs (docs/decisions.md 191): A and the
// NTT of s1, s2 and t0 once, before the first round, and each round reads
// them from ex. The rounds write the bytes sign_rounds writes. ex.key is
// secret and is wiped on every path. ex.a_hat is A, which pk's rho gives
// to every reader, so it is not wiped. The frame holds ex and the round,
// and it may not be inlined either.
static __attribute__((noinline)) unsigned
sign_rounds_expanded(uint32_t cpu, uint8_t sig[MLDSA87_SIG_LEN], const uint8_t sk[MLDSA87_SK_LEN],
                     const uint8_t mu[MLDSA_MU_LEN], const uint8_t rnd[MLDSA87_RND_LEN]) {
    mlds_expanded ex;
    mlds_round st;
    st.cpu = cpu;
    st.ex = &ex;
    uint8_t rho2[64];
    private_seed(cpu, rho2, sk, mu, rnd);
    uint32_t usable = mlds_expand(&ex, cpu, sk);
    CT_DECLASSIFY(&usable, sizeof usable);
    unsigned rounds = usable == 1 ? rejection_loop(&st, sig, sk, mu, rho2) : 0;
    ct_wipe(&st, sizeof st);
    ct_wipe(&ex.key, sizeof ex.key);
    ct_wipe(rho2, sizeof rho2);
    return rounds;
}
#endif

// The signer's loop for the object: sign_rounds_expanded in a host object
// and sign_rounds in every other object.
static unsigned signature_rounds(uint32_t cpu, uint8_t sig[MLDSA87_SIG_LEN],
                                 const uint8_t sk[MLDSA87_SK_LEN], const uint8_t mu[MLDSA_MU_LEN],
                                 const uint8_t rnd[MLDSA87_RND_LEN]) {
#ifdef CH_CPU_RUNTIME
    return sign_rounds_expanded(cpu, sig, sk, mu, rnd);
#else
    return sign_rounds(cpu, sig, sk, mu, rnd);
#endif
}

// mldsa87_verify of a signature just made, with the hashes on cpu in a host
// object (mldsa.h).
static int verify_with(uint32_t cpu, const uint8_t *pk, size_t pk_len, const uint8_t *msg,
                       size_t msg_len, const uint8_t *ctx, size_t ctx_len,
                       const uint8_t sig[MLDSA87_SIG_LEN]) {
#ifdef CH_CPU_RUNTIME
    return mldsa87_verify_cpu(cpu, pk, pk_len, msg, msg_len, ctx, ctx_len, sig, MLDSA87_SIG_LEN);
#else
    (void)cpu;
    return mldsa87_verify(pk, pk_len, msg, msg_len, ctx, ctx_len, sig, MLDSA87_SIG_LEN);
#endif
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
// step 6, over Algorithm 2's M'), the loop under cpu, and the check under
// pk.
static unsigned sign_checked(uint32_t cpu, uint8_t sig[MLDSA87_SIG_LEN], const uint8_t *sk,
                             size_t sk_len, const uint8_t *pk, size_t pk_len, const uint8_t *msg,
                             size_t msg_len, const uint8_t *ctx, size_t ctx_len,
                             const uint8_t rnd[MLDSA87_RND_LEN]) {
    if (sk_len != MLDSA87_SK_LEN || pk_len != MLDSA87_PK_LEN || ctx_len > MLDSA_CONTEXT_MAX) {
        ct_wipe(sig, MLDSA87_SIG_LEN);
        return 0;
    }
    const uint8_t prefix[2] = {0, (uint8_t)ctx_len};
    uint8_t mu[MLDSA_MU_LEN];
    shake h;
    shake256_init(&h);
    mld_absorb(cpu, &h, sk + MLDS_SK_TR_AT, 64);
    mld_absorb(cpu, &h, prefix, sizeof prefix);
    mld_absorb(cpu, &h, ctx, ctx_len);
    mld_absorb(cpu, &h, msg, msg_len);
    mld_squeeze(cpu, &h, mu, sizeof mu);
    unsigned rounds = signature_rounds(cpu, sig, sk, mu, rnd);
    if (rounds == 0 || !verify_with(cpu, pk, pk_len, msg, msg_len, ctx, ctx_len, sig)) {
        ct_wipe(sig, MLDSA87_SIG_LEN);
        return 0;
    }
    return rounds;
}

// mldsa87_sign under cpu: the checks of the caller's arguments, then the
// signature.
static int sign_entry(uint32_t cpu, uint8_t sig[MLDSA87_SIG_LEN], const uint8_t *sk, size_t sk_len,
                      const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len,
                      const uint8_t *ctx, size_t ctx_len, const uint8_t rnd[MLDSA87_RND_LEN]) {
    CH_ASSERT(sig != NULL && sk != NULL && pk != NULL && rnd != NULL);
    CH_ASSERT(msg != NULL || msg_len == 0);
    CH_ASSERT(ctx != NULL || ctx_len == 0);
    CH_ASSERT(rnd_drawn(rnd));
    return sign_checked(cpu, sig, sk, sk_len, pk, pk_len, msg, msg_len, ctx, ctx_len, rnd) != 0;
}

int mldsa87_sign(uint8_t sig[MLDSA87_SIG_LEN], const uint8_t *sk, size_t sk_len, const uint8_t *pk,
                 size_t pk_len, const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
                 size_t ctx_len, const uint8_t rnd[MLDSA87_RND_LEN]) {
    return sign_entry(0, sig, sk, sk_len, pk, pk_len, msg, msg_len, ctx, ctx_len, rnd);
}

#ifdef CH_CPU_RUNTIME
int mldsa87_sign_cpu(uint32_t cpu, uint8_t sig[MLDSA87_SIG_LEN], const uint8_t *sk, size_t sk_len,
                     const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len,
                     const uint8_t *ctx, size_t ctx_len, const uint8_t rnd[MLDSA87_RND_LEN]) {
    return sign_entry(cpu, sig, sk, sk_len, pk, pk_len, msg, msg_len, ctx, ctx_len, rnd);
}
#endif

#ifdef CH_MLDSA_SIGN_TEST
int mldsa87_sign_any_rnd(uint8_t sig[MLDSA87_SIG_LEN], const uint8_t *sk, size_t sk_len,
                         const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len,
                         const uint8_t *ctx, size_t ctx_len, const uint8_t rnd[MLDSA87_RND_LEN]) {
    return sign_checked(0, sig, sk, sk_len, pk, pk_len, msg, msg_len, ctx, ctx_len, rnd) != 0;
}

// mldsa87_challenge with the hashes on cpu in a host object (mldsa.h).
static int challenge_with(uint32_t cpu, uint8_t c_tilde[MLDSA87_CTILDE_LEN],
                          const uint8_t pk[MLDSA87_PK_LEN], const uint8_t mu[MLDSA_MU_LEN],
                          const uint8_t sig[MLDSA87_SIG_LEN]) {
#ifdef CH_CPU_RUNTIME
    return mldsa87_challenge_cpu(cpu, c_tilde, pk, mu, sig);
#else
    (void)cpu;
    return mldsa87_challenge(c_tilde, pk, mu, sig);
#endif
}

// mldsa87_sign_mu under cpu: on the object's loop, or on sign_rounds when
// device is 1 in a host object.
static unsigned sign_mu(uint32_t cpu, int device, uint8_t sig[MLDSA87_SIG_LEN],
                        const uint8_t sk[MLDSA87_SK_LEN], const uint8_t pk[MLDSA87_PK_LEN],
                        const uint8_t mu[MLDSA_MU_LEN], const uint8_t rnd[MLDSA87_RND_LEN]) {
    unsigned rounds =
        device ? sign_rounds(cpu, sig, sk, mu, rnd) : signature_rounds(cpu, sig, sk, mu, rnd);
    uint8_t c_tilde[MLDSA87_CTILDE_LEN];
    if (rounds == 0 || !challenge_with(cpu, c_tilde, pk, mu, sig) ||
        ct_memeq(c_tilde, sig, MLDSA87_CTILDE_LEN) != 1) {
        ct_wipe(sig, MLDSA87_SIG_LEN);
        return 0;
    }
    return rounds;
}

unsigned mldsa87_sign_mu(uint8_t sig[MLDSA87_SIG_LEN], const uint8_t sk[MLDSA87_SK_LEN],
                         const uint8_t pk[MLDSA87_PK_LEN], const uint8_t mu[MLDSA_MU_LEN],
                         const uint8_t rnd[MLDSA87_RND_LEN]) {
    return sign_mu(0, 0, sig, sk, pk, mu, rnd);
}

#ifdef CH_CPU_RUNTIME
int mldsa87_sign_any_rnd_cpu(uint32_t cpu, uint8_t sig[MLDSA87_SIG_LEN], const uint8_t *sk,
                             size_t sk_len, const uint8_t *pk, size_t pk_len, const uint8_t *msg,
                             size_t msg_len, const uint8_t *ctx, size_t ctx_len,
                             const uint8_t rnd[MLDSA87_RND_LEN]) {
    return sign_checked(cpu, sig, sk, sk_len, pk, pk_len, msg, msg_len, ctx, ctx_len, rnd) != 0;
}

unsigned mldsa87_sign_mu_cpu(uint32_t cpu, uint8_t sig[MLDSA87_SIG_LEN],
                             const uint8_t sk[MLDSA87_SK_LEN], const uint8_t pk[MLDSA87_PK_LEN],
                             const uint8_t mu[MLDSA_MU_LEN], const uint8_t rnd[MLDSA87_RND_LEN]) {
    return sign_mu(cpu, 0, sig, sk, pk, mu, rnd);
}

unsigned mldsa87_sign_mu_device_cpu(uint32_t cpu, uint8_t sig[MLDSA87_SIG_LEN],
                                    const uint8_t sk[MLDSA87_SK_LEN],
                                    const uint8_t pk[MLDSA87_PK_LEN],
                                    const uint8_t mu[MLDSA_MU_LEN],
                                    const uint8_t rnd[MLDSA87_RND_LEN]) {
    return sign_mu(cpu, 1, sig, sk, pk, mu, rnd);
}
#endif
#endif
