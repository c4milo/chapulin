// ch_jws_sign, the JWS signer for tests and tools. jws.h states the
// contract. This file hashes the JWS Signing Input, checks the key's form
// and picks the signer: p256_sign.c's hedged ECDSA and rsa_pkcs1.c's
// RSASSA-PKCS1-v1_5 over the RSA signers a server runs. It sits apart from
// jws.c, which checks signatures over public inputs alone: a private key
// and the noise pass through this file. Outside a JWS build it holds
// nothing, and jws.h's includes keep the unit from being empty. So does
// an object with no server role, which holds no signer.
#include "jws.h"

#if defined(CH_JWS) && defined(CH_ROLE_SERVER)

#include "cpu.h"
#include "ct.h"
#include "ed25519_sign.h"
#include "p256_sign.h"
#include "rsa_pkcs1.h"
#include "sha256.h"

_Static_assert(CH_JWS_NOISE_LEN == P256_NOISE_LEN, "jws.h states the ECDSA nonce's noise length");
_Static_assert(CH_JWS_NOISE_LEN >= RSA_BLIND_LEN, "the noise holds the RSA exponents' blinding");

#define ES256_SIG_LEN 64
#define ED25519_SEED_LEN 32
#define ED25519_SIG_LEN 64

// SHA-256 of the JWS Signing Input, which RS256 and ES256 sign. The input
// is the token's public text, so the state is not wiped.
static void hash_input(const uint8_t *input, size_t input_len, uint8_t digest[SHA256_LEN]) {
    sha256 s;
    sha256_init(&s);
    if (input_len != 0) {
        sha256_update(&s, input, input_len);
    }
    sha256_final(&s, digest);
}

// RFC 7518 section 3.4. priv is the 32-byte scalar, and the signer's key
// test holds it to 1 to n-1.
static int sign_es256(uint32_t cpu, const void *priv, size_t priv_len, const uint8_t *noise,
                      const uint8_t *input, size_t input_len, uint8_t *sig, size_t sig_cap,
                      size_t *sig_len) {
    if (priv_len != P256_PRIV_LEN || noise == NULL) {
        return CH_EINVAL;
    }
    if (sig_cap < ES256_SIG_LEN) {
        return CH_ECAP;
    }
    uint8_t digest[SHA256_LEN];
    hash_input(input, input_len, digest);
    uint8_t candidate[ES256_SIG_LEN];
    if (!p256_sign_hedged_raw_cpu(cpu, priv, digest, noise, candidate)) {
        return CH_EINVAL;
    }
    for (size_t i = 0; i < sizeof candidate; i++) {
        sig[i] = candidate[i];
    }
    *sig_len = sizeof candidate;
    return CH_OK;
}

// RFC 7518 section 3.3. priv is one ch_rsa_priv, whose n_len the signer's
// key test holds to 256 bytes or more, RFC 7518's 2048 bits. The first
// RSA_BLIND_LEN bytes of the noise blind the exponents.
static int sign_rs256(uint32_t cpu, const void *priv, size_t priv_len, const uint8_t *noise,
                      const uint8_t *input, size_t input_len, uint8_t *sig, size_t sig_cap,
                      size_t *sig_len) {
    if (priv_len != sizeof(ch_rsa_priv) || noise == NULL) {
        return CH_EINVAL;
    }
    const ch_rsa_priv *key = priv;
    // The length is public: a signature is as long as the modulus.
    size_t n_len = key->n_len;
    if (n_len > CH_RSA_MODULUS_MAX) {
        return CH_EINVAL;
    }
    if (sig_cap < n_len) {
        return CH_ECAP;
    }
    uint8_t digest[SHA256_LEN];
    hash_input(input, input_len, digest);
    uint8_t candidate[CH_RSA_MODULUS_MAX];
    int rc = CH_EINVAL;
    if (rsa_pkcs1_sign(cpu, key, digest, noise, candidate)) {
        for (size_t i = 0; i < n_len; i++) {
            sig[i] = candidate[i];
        }
        *sig_len = n_len;
        rc = CH_OK;
    }
    // A candidate that failed its check is what a fault made of the key.
    ct_wipe(candidate, sizeof candidate);
    return rc;
}

// RFC 8037 section 3.1: Ed25519 over the JWS Signing Input itself. priv is
// the 32-byte seed. The signer runs on the wide field alone, so a cpu
// value without the multiply bit has no signer here. EdDSA draws nothing,
// so it reads no noise.
static int sign_eddsa(uint32_t cpu, const void *priv, size_t priv_len, const uint8_t *input,
                      size_t input_len, uint8_t *sig, size_t sig_cap, size_t *sig_len) {
    if (priv_len != ED25519_SEED_LEN || (cpu & CH_CPU_CONSTANT_TIME_MULTIPLY) == 0) {
        return CH_EINVAL;
    }
    if (sig_cap < ED25519_SIG_LEN) {
        return CH_ECAP;
    }
    uint8_t candidate[ED25519_SIG_LEN];
    int rc = CH_EINVAL;
    if (ed25519_sign(priv, input, input_len, candidate)) {
        for (size_t i = 0; i < sizeof candidate; i++) {
            sig[i] = candidate[i];
        }
        *sig_len = sizeof candidate;
        rc = CH_OK;
    }
    ct_wipe(candidate, sizeof candidate);
    return rc;
}

int ch_jws_sign(uint32_t cpu, uint8_t algorithm, const void *priv, size_t priv_len,
                const uint8_t noise[CH_JWS_NOISE_LEN], const uint8_t *input, size_t input_len,
                uint8_t *sig, size_t sig_cap, size_t *sig_len) {
    // The caller's description of its CPU picks the multiply each signer
    // runs, so a value the object refuses is refused before a key is read.
    if (!cpu_value_ok(cpu) || priv == NULL) {
        return CH_EINVAL;
    }
    switch (algorithm) {
    case CH_JWS_RS256:
        return sign_rs256(cpu, priv, priv_len, noise, input, input_len, sig, sig_cap, sig_len);
    case CH_JWS_ES256:
        return sign_es256(cpu, priv, priv_len, noise, input, input_len, sig, sig_cap, sig_len);
    case CH_JWS_EDDSA:
        return sign_eddsa(cpu, priv, priv_len, input, input_len, sig, sig_cap, sig_len);
    default:
        return CH_EINVAL;
    }
}

#endif // CH_JWS && CH_ROLE_SERVER
