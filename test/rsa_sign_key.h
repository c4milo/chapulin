// Loads a key of test/rsa_sign_vectors.h into a ch_rsa_priv: the modulus
// and the private exponent, and in a host build the five integers of the
// Chinese remainder theorem, which that build's key holds (rsa_sign.h). A
// host session that states its multiply signs with the five, so a test
// that left them zero would have its key refused there.
#ifndef CH_TEST_RSA_SIGN_KEY_H
#define CH_TEST_RSA_SIGN_KEY_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "rsa_sign.h"
#include "rsa_sign_vectors.h"

// One key's seven integers, as the vectors' arrays.
typedef struct {
    const uint8_t *n;
    const uint8_t *d;
    size_t n_len;
    const uint8_t *p;
    const uint8_t *q;
    const uint8_t *dp;
    const uint8_t *dq;
    const uint8_t *qinv;
} test_rsa_sign_key;

// The key the vectors name rsa_sign_<bits>.
#define TEST_RSA_SIGN_KEY(bits)                                                                    \
    {                                                                                              \
        rsa_sign_##bits##_n,  rsa_sign_##bits##_d,   sizeof rsa_sign_##bits##_n,                   \
        rsa_sign_##bits##_p,  rsa_sign_##bits##_q,   rsa_sign_##bits##_dp,                         \
        rsa_sign_##bits##_dq, rsa_sign_##bits##_qinv}

// priv = the vector key, with every byte past its integers zero. The
// vector's modulus must fit this build's ch_rsa_priv.
static inline void test_rsa_sign_key_load(ch_rsa_priv *priv, const test_rsa_sign_key *from) {
    memset(priv, 0, sizeof *priv);
    memcpy(priv->n, from->n, from->n_len);
    memcpy(priv->d, from->d, from->n_len);
    priv->n_len = from->n_len;
#ifdef CH_CPU_RUNTIME
    size_t half_len = from->n_len / 2;
    memcpy(priv->p, from->p, half_len);
    memcpy(priv->q, from->q, half_len);
    memcpy(priv->dp, from->dp, half_len);
    memcpy(priv->dq, from->dq, half_len);
    memcpy(priv->qinv, from->qinv, half_len);
#endif
}

// priv's five CRT integers = the bytes at crt: p, q, dp, dq and qinv in
// that order with nothing between them, each half as long as the modulus
// priv already holds. A device build's key holds none of the five, so
// there the call reads and writes nothing.
#ifdef CH_CPU_RUNTIME
static inline void test_rsa_sign_key_load_crt(ch_rsa_priv *priv, const uint8_t *crt) {
    size_t half_len = priv->n_len / 2;
    memcpy(priv->p, crt, half_len);
    memcpy(priv->q, crt + half_len, half_len);
    memcpy(priv->dp, crt + 2 * half_len, half_len);
    memcpy(priv->dq, crt + 3 * half_len, half_len);
    memcpy(priv->qinv, crt + 4 * half_len, half_len);
}
#else
static inline void test_rsa_sign_key_load_crt(const ch_rsa_priv *priv, const uint8_t *crt) {
    (void)priv;
    (void)crt;
}
#endif

// The RSA-2048 key, which every server test provisions.
static inline void test_rsa_sign_key_2048(ch_rsa_priv *priv) {
    static const test_rsa_sign_key from = TEST_RSA_SIGN_KEY(2048);
    test_rsa_sign_key_load(priv, &from);
}

#endif
