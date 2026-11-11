// The JWS signature check and base64url. jws.h states the contract. This
// file hashes the JWS Signing Input, reads the key and picks the
// verifier; the verifiers are rsa_pkcs1.c's, p256.c's and
// x25519_wide.c's, which dnssec.c calls too. Outside a JWS build it holds
// nothing, and jws.h's includes keep the unit from being empty.
#include "jws.h"

#ifdef CH_JWS

#include "base64_codec.h"
#include "ed25519_verify.h"
#include "p256.h"
#include "rsa.h"
#include "rsa_key_field.h"
#include "rsa_pkcs1.h"
#include "sha256.h"
#include "sha512.h"

// jws.h states the bounds, and the code below them holds each one.
_Static_assert(CH_JWS_RSA_EXPONENT_LEN_MAX == RSA_KEY_FIELD_EXPONENT_MAX,
               "jws.h states the reader's exponent bound");
_Static_assert(CH_JWS_RSA_MODULUS_LEN_MAX == CH_RSA_MODULUS_MAX,
               "jws.h states the verifier's modulus bound");

// The lengths RFC 7518 section 3.4 and RFC 8037 fix.
#define ES256_KEY_LEN 64
#define ES256_SIG_LEN 64
#define ED25519_KEY_LEN 32
#define ED25519_SIG_LEN 64

// SHA-256 of the JWS Signing Input, which RS256 and ES256 sign. An empty
// input adds no bytes, and its pointer may be NULL.
static void hash_input(const uint8_t *input, size_t input_len, uint8_t digest[SHA256_LEN]) {
    sha256 s;
    sha256_init(&s);
    if (input_len != 0) {
        sha256_update(&s, input, input_len);
    }
    sha256_final(&s, digest);
}

// RFC 7518 section 3.3. The key's bounds come first, and a key outside
// them is the caller's to correct. rsa_pkcs1_verify_exponent then refuses
// a signature that is not as long as the modulus or not below it.
static int verify_rs256(const uint8_t *key, size_t key_len, const uint8_t *input,
                        size_t input_len, const uint8_t *sig, size_t sig_len) {
    rsa_key_field k;
    if (!rsa_key_field_read(key, key_len, &k) || k.e < 3 || (k.e & 1) == 0 ||
        k.n_len < CH_JWS_RSA_MODULUS_LEN_MIN || k.n_len > CH_JWS_RSA_MODULUS_LEN_MAX ||
        (k.n[k.n_len - 1] & 1) == 0) {
        return CH_EINVAL;
    }
    uint8_t digest[SHA256_LEN];
    hash_input(input, input_len, digest);
    return rsa_pkcs1_verify_exponent(k.n, k.n_len, k.e, digest, sizeof digest, sig, sig_len)
               ? CH_OK
               : CH_EAUTH;
}

// RFC 7518 section 3.4: the signature is R then S, with no DER.
static int verify_es256(const uint8_t *key, size_t key_len, const uint8_t *input,
                        size_t input_len, const uint8_t *sig, size_t sig_len) {
    if (key_len != ES256_KEY_LEN) {
        return CH_EINVAL;
    }
    if (sig_len != ES256_SIG_LEN) {
        return CH_EAUTH;
    }
    uint8_t digest[SHA256_LEN];
    hash_input(input, input_len, digest);
    return p256_ecdsa_verify_raw(key, digest, sig) ? CH_OK : CH_EAUTH;
}

// RFC 8037 section 3.1: Ed25519 over the JWS Signing Input itself. RFC
// 8032 section 5.1.7 hashes R, then the key A, then the message.
static int verify_eddsa(const uint8_t *key, size_t key_len, const uint8_t *input,
                        size_t input_len, const uint8_t *sig, size_t sig_len) {
    if (key_len != ED25519_KEY_LEN) {
        return CH_EINVAL;
    }
    if (sig_len != ED25519_SIG_LEN) {
        return CH_EAUTH;
    }
    sha512 s;
    sha512_init(&s);
    sha512_update(&s, sig, 32); // R
    sha512_update(&s, key, ED25519_KEY_LEN);
    if (input_len != 0) {
        sha512_update(&s, input, input_len);
    }
    uint8_t hram[SHA512_LEN];
    sha512_final(&s, hram);
    return ed25519_verify_hram(key, hram, sig) ? CH_OK : CH_EAUTH;
}

int ch_jws_verify(uint8_t algorithm, const uint8_t *key, size_t key_len, const uint8_t *input,
                  size_t input_len, const uint8_t *sig, size_t sig_len) {
    switch (algorithm) {
    case CH_JWS_RS256:
        return verify_rs256(key, key_len, input, input_len, sig, sig_len);
    case CH_JWS_ES256:
        return verify_es256(key, key_len, input, input_len, sig, sig_len);
    case CH_JWS_EDDSA:
        return verify_eddsa(key, key_len, input, input_len, sig, sig_len);
    default:
        return CH_EINVAL;
    }
}

// The two base64url calls are base64_codec.c's, under jws.h's names.
int ch_base64url_encode(const uint8_t *in, size_t in_len, uint8_t *text, size_t text_cap,
                        size_t *text_len) {
    return base64url_encode(in, in_len, text, text_cap, text_len);
}

int ch_base64url_decode(const uint8_t *text, size_t text_len, uint8_t *out, size_t out_cap,
                        size_t *out_len) {
    return base64url_decode(text, text_len, out, out_cap, out_len);
}

#endif // CH_JWS
