// ML-DSA-87 signature verification (FIPS 204), the signature CNSA 2.0
// names for PROFILE=cnsa2 (docs/decisions.md 154). Verification alone:
// no signing, no secret. Every input is public: the key, the message, the
// context and the signature. So the arithmetic carries no constant-time
// burden, as in p256.c and rsa.c.
//
// ML-DSA-87 is FIPS 204 Table 1's parameter set at security category 5:
// k = 8, l = 7, eta = 2, tau = 60, beta = 120, gamma1 = 2^19,
// gamma2 = (q - 1) / 32 and omega = 75. A public key is 2592 bytes and a
// signature 4627 bytes. This is pure ML-DSA with a context string (FIPS
// 204 Algorithm 3), and TLS signs with an empty context.
//
// mldsa.c and mldsa_poly.c compile into test binaries alone until a TRUST
// value runs them.
#ifndef CH_MLDSA_H
#define CH_MLDSA_H

#include <stddef.h>
#include <stdint.h>

#define MLDSA87_PK_LEN 2592   // rho, then t1 at 10 bits a coefficient
#define MLDSA87_SIG_LEN 4627  // c-tilde, then z at 20 bits, then the hints
#define MLDSA87_CTILDE_LEN 64 // lambda / 4 bytes, lambda = 256
#define MLDSA_MU_LEN 64       // mu, the message representative
#define MLDSA_CONTEXT_MAX 255 // the longest context FIPS 204 Algorithm 3 takes

// Returns 1 when sig is a valid ML-DSA-87 signature of msg under pk and
// the context ctx, and 0 for anything else (FIPS 204 Algorithm 3,
// ML-DSA.Verify). A pk_len other than MLDSA87_PK_LEN, a sig_len other than
// MLDSA87_SIG_LEN and a ctx_len over MLDSA_CONTEXT_MAX each give 0.
// msg and ctx may be null when their lengths are 0.
int mldsa87_verify(const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len,
                   const uint8_t *ctx, size_t ctx_len, const uint8_t *sig, size_t sig_len);

// The challenge FIPS 204 Algorithm 8 (ML-DSA.Verify_internal) computes
// again: c_tilde' = H(mu || w1Encode(w1'), 64). Returns 1 and writes it
// when the signature's hints are well formed and its z is under
// gamma1 - beta. Returns 0 and writes nothing for any other signature, and
// for a key or a challenge whose sampling stops at its bound
// (docs/decisions.md 154). mldsa87_verify accepts exactly when this
// returns 1 and c_tilde' is the signature's first 64 bytes. The
// differential compares c_tilde' with the Lean model's.
int mldsa87_challenge(uint8_t c_tilde[MLDSA87_CTILDE_LEN], const uint8_t pk[MLDSA87_PK_LEN],
                      const uint8_t mu[MLDSA_MU_LEN], const uint8_t sig[MLDSA87_SIG_LEN]);

#endif
