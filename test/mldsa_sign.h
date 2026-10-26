// An ML-DSA-87 signer for tests alone (FIPS 204 Algorithms 6 and 7,
// ML-DSA.KeyGen_internal and ML-DSA.Sign_internal). chapulin verifies and
// never signs ML-DSA, so no library source calls this, and no build
// packages it. The mock servers of test/cnsa2_test.c and
// test/cnsa2_quic_test.c sign their CertificateVerify with it, over a
// transcript that changes with each hello, and the CA tests sign their
// chains with it. bin/mldsa_sign_test holds it to Wycheproof's
// deterministic signatures and keys, every one, so the signatures the
// mocks send are FIPS 204's and not this file's own reading of it.
//
// Nothing here is constant time: a test key is public.
#ifndef CH_TEST_MLDSA_SIGN_H
#define CH_TEST_MLDSA_SIGN_H

#include <stddef.h>
#include <stdint.h>

#include "mldsa.h"
#include "mldsa_poly.h"

// The expanded private key: the parts of FIPS 204's sk, unpacked, with
// the public key beside them.
typedef struct {
    uint8_t pk[MLDSA87_PK_LEN];
    uint8_t rho[MLD_RHO_BYTES];
    uint8_t key[32];
    uint8_t tr[64];
    mld_poly s1_hat[MLD_L]; // NTT(s1)
    mld_poly s2_hat[MLD_K]; // NTT(s2)
    mld_poly t0_hat[MLD_K]; // NTT(t0)
} mldsa_test_key;

// ML-DSA.KeyGen_internal from the 32-byte seed xi.
void mldsa_test_keygen(mldsa_test_key *k, const uint8_t seed[32]);

// ML-DSA.Sign over M' = 0 || ctx_len || ctx || msg, with the 32 bytes of
// rnd, which are all 0 for the deterministic variant. Returns 1 and
// writes sig, or 0 when the rejection loop passes 1000 rounds or
// SampleInBall stops at its bound.
int mldsa_test_sign(const mldsa_test_key *k, const uint8_t *msg, size_t msg_len, const uint8_t *ctx,
                    size_t ctx_len, const uint8_t rnd[32], uint8_t sig[MLDSA87_SIG_LEN]);

// The same from mu, the message representative, as Sign_internal takes
// it after step 6.
int mldsa_test_sign_mu(const mldsa_test_key *k, const uint8_t mu[64], const uint8_t rnd[32],
                       uint8_t sig[MLDSA87_SIG_LEN]);

#endif
