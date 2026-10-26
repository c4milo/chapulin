// ML-DSA-87 key generation and signing (FIPS 204 Algorithms 2, 6 and 7),
// the signing half of the signature CNSA 2.0 names for PROFILE=cnsa2
// (docs/decisions.md 159). mldsa.[ch] verifies. This file shares the
// verifier's sampler of A and its hashes, whose inputs are public, and
// none of its arithmetic: every operation on s1, s2, t0, K, y or c runs on
// mldsa_sign_poly.c and mldsa_sign_pack.c, which branch on no secret and
// index no memory with one.
//
// What the constant-time claim covers. The time and the addresses of key
// generation do not depend on the seed. The time and the addresses of one
// round of the rejection loop do not depend on the key, on rnd or on the
// round's y and c. What shows is the count of rounds: FIPS 204 section
// 3.6.3 and Appendix C treat it as public, because it depends on the
// key, the message and rnd through a hash alone. The signature is public,
// and its encoding reads the hint positions of the round that passed.
//
// Hedged signing. The caller draws rnd, 32 bytes, through rand_draw for
// each signature, as srv_auth.c draws the P-256 signer's Z
// (docs/decisions.md 153). mldsa87_sign refuses rnd of 32 zero bytes with
// CH_ASSERT, as a draw site refuses a source that wrote nothing (INV-4),
// so no library call signs deterministically. The deterministic variant
// of FIPS 204 is callable only in a test binary, through the entries
// that CH_MLDSA_SIGN_TEST declares below.
//
// The check before a signature leaves (docs/decisions.md 159).
// mldsa87_sign verifies each signature with mldsa87_verify under the
// caller's public key before it returns. On a failure it writes zero to
// sig and returns 0, so a fault in signing gives no signature.
//
// mldsa_signer.c and its four files compile into test binaries alone until
// the PROFILE=cnsa2 server role packages them.
#ifndef CH_MLDSA_SIGNER_H
#define CH_MLDSA_SIGNER_H

#include <stddef.h>
#include <stdint.h>

#include "mldsa.h"

#define MLDSA87_SEED_LEN 32 // xi, the seed key generation expands
#define MLDSA87_SK_LEN 4896 // rho, K, tr, s1, s2 and t0 (FIPS 204 Table 2)
#define MLDSA87_RND_LEN 32  // the hedge, FIPS 204 Algorithm 2's rnd
// The rounds of the rejection loop before signing stops: FIPS 204 Appendix
// C Table 3's limit for ML-DSA.Sign_internal. A round passes with a
// probability near 1 / 3.85, so all 814 fail with a probability below
// 2^-256.
#define MLDSA87_SIGN_ROUNDS 814

// FIPS 204 Algorithm 6, ML-DSA.KeyGen_internal: expands seed into the
// secret key sk (skEncode, Algorithm 24) and the public key pk (pkEncode,
// Algorithm 22). Returns 1. Returns 0, with sk and pk zeroed, when a
// sampler of s1, s2 or A stops at its bound, which a correct SHAKE does
// with a probability below 2^-256. Every copy of a secret that the call
// makes is wiped before it returns. seed stays the caller's to wipe.
int mldsa87_keygen(uint8_t sk[MLDSA87_SK_LEN], uint8_t pk[MLDSA87_PK_LEN],
                   const uint8_t seed[MLDSA87_SEED_LEN]);

// FIPS 204 Algorithm 2, ML-DSA.Sign, hedged, pure ML-DSA with the context
// ctx: signs msg under sk with the caller's rnd, and verifies the
// signature under pk. Returns 1 and writes sig. Returns 0, with sig
// zeroed, for:
//  - an sk_len other than MLDSA87_SK_LEN, a pk_len other than
//    MLDSA87_PK_LEN, or a ctx_len over MLDSA_CONTEXT_MAX;
//  - an sk whose s1 or s2 holds a coefficient outside [-2, 2], which
//    skDecode would decode out of range (FIPS 204 section 7.2);
//  - 814 rounds with no signature, or a sampler at its bound;
//  - a signature that mldsa87_verify refuses under pk, such as one a
//    fault changed, or one under an sk that is not pk's.
// rnd of 32 zero bytes stops the call with CH_ASSERT. msg and ctx may be
// null when their lengths are 0.
int mldsa87_sign(uint8_t sig[MLDSA87_SIG_LEN], const uint8_t *sk, size_t sk_len, const uint8_t *pk,
                 size_t pk_len, const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
                 size_t ctx_len, const uint8_t rnd[MLDSA87_RND_LEN]);

#ifdef CH_MLDSA_SIGN_TEST
// Test binaries alone. The Makefile passes CH_MLDSA_SIGN_TEST to no
// library object, so no packaged object holds these symbols.
//
// mldsa87_sign without the refusal of zero rnd: FIPS 204's deterministic
// variant when rnd is 32 zero bytes. The rest is mldsa87_sign's.
int mldsa87_sign_any_rnd(uint8_t sig[MLDSA87_SIG_LEN], const uint8_t *sk, size_t sk_len,
                         const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len,
                         const uint8_t *ctx, size_t ctx_len, const uint8_t rnd[MLDSA87_RND_LEN]);

// FIPS 204 Algorithm 7, ML-DSA.Sign_internal, from mu, with any rnd. It
// checks the signature as mldsa87_verify does after mu: the challenge
// that mldsa87_challenge recomputes under pk must be the signature's.
// Returns the count of rounds the signature took, 1 to 814, or 0 as
// mldsa87_sign does. The timing rows read the count.
unsigned mldsa87_sign_mu(uint8_t sig[MLDSA87_SIG_LEN], const uint8_t sk[MLDSA87_SK_LEN],
                         const uint8_t pk[MLDSA87_PK_LEN], const uint8_t mu[MLDSA_MU_LEN],
                         const uint8_t rnd[MLDSA87_RND_LEN]);
#endif

#endif
