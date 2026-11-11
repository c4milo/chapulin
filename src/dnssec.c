// The DNSSEC hash and signature check. dnssec.h states the contract.
// This file reads the DNSKEY's key field and picks the hash and the
// verifier; the verifiers are rsa_pkcs1.c's and p256.c's. Outside a
// DNSSEC build it holds nothing, and dnssec.h's hash headers keep the
// unit from being empty.
#include "dnssec.h"

#ifdef CH_DNSSEC

#include "ct.h"
#include "dnssec_hash.h"
#include "ed25519_verify.h"
#include "p256.h"
#include "p384.h"
#include "rsa.h"
#include "rsa_key_field.h"
#include "rsa_pkcs1.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"

// rsa_key_field.h reads the DNSKEY's RSA key field, RFC 3110 section 2's
// form, and refuses an exponent longer than dnssec.h states.
_Static_assert(CH_DNSSEC_RSA_EXPONENT_MAX == RSA_KEY_FIELD_EXPONENT_MAX,
               "dnssec.h states the reader's exponent bound");

static int verify_rsa(const uint8_t *key, size_t key_len, const uint8_t *digest, size_t digest_len,
                      const uint8_t *sig, size_t sig_len) {
    rsa_key_field k;
    if (!rsa_key_field_read(key, key_len, &k) || k.e < 3 || (k.e & 1) == 0 ||
        k.n_len < CH_DNSSEC_RSA_MODULUS_MIN || k.n_len > CH_RSA_MODULUS_MAX ||
        (k.n[k.n_len - 1] & 1) == 0) {
        return CH_EINVAL;
    }
    return rsa_pkcs1_verify_exponent(k.n, k.n_len, k.e, digest, digest_len, sig, sig_len)
               ? CH_OK
               : CH_EAUTH;
}

// What ch_dnssec_digest_init stores for digest type 1: a value no DNSSEC
// algorithm number takes, because no signature this file checks runs on
// SHA-1.
#define HASH_SHA1 0xf1

// 1 for a hash that ch_dnssec_digest_init started as SHA-1.
static int hashes_sha1(uint8_t algorithm) {
    return algorithm == HASH_SHA1;
}

// 1 for the algorithms whose hash runs on a SHA-512 context: SHA-512 for
// 10 and 15, and SHA-384 for 14.
static int hashes_sha512(uint8_t algorithm) {
    return algorithm == CH_DNSSEC_ALG_RSASHA512 || algorithm == CH_DNSSEC_ALG_ED25519 ||
           algorithm == CH_DNSSEC_ALG_ECDSAP384SHA384;
}

static int dnssec_hash_init(ch_dnssec_hash_priv *h, uint8_t algorithm, const uint8_t *key, size_t key_len,
                        const uint8_t *sig, size_t sig_len) {
    h->algorithm = algorithm;
    switch (algorithm) {
    case CH_DNSSEC_ALG_RSASHA256:
    case CH_DNSSEC_ALG_ECDSAP256SHA256:
        sha256_init(&h->state.sha256_state);
        return CH_OK;
    case CH_DNSSEC_ALG_RSASHA512:
        sha512_init(&h->state.sha512_state);
        return CH_OK;
    case CH_DNSSEC_ALG_ECDSAP384SHA384:
        sha384_init(&h->state.sha512_state);
        return CH_OK;
    case CH_DNSSEC_ALG_ED25519:
        if (key_len != 32 || sig_len != 64) {
            return CH_EINVAL;
        }
        sha512_init(&h->state.sha512_state);
        sha512_update(&h->state.sha512_state, sig, 32); // R
        sha512_update(&h->state.sha512_state, key, 32); // A
        return CH_OK;
    default:
        return CH_EINVAL;
    }
}

// Type 1 is SHA-1 under HASH_SHA1. Types 2 and 4 are the hashes of
// algorithms 8 and 14, whose init reads no key and no signature.
static int dnssec_digest_init(ch_dnssec_hash_priv *h, uint8_t digest_type) {
    switch (digest_type) {
    case CH_DNSSEC_DIGEST_SHA1:
        h->algorithm = HASH_SHA1;
        sha1_init(&h->state.sha1_state);
        return CH_OK;
    case CH_DNSSEC_DIGEST_SHA256:
        return dnssec_hash_init(h, CH_DNSSEC_ALG_RSASHA256, NULL, 0, NULL, 0);
    case CH_DNSSEC_DIGEST_SHA384:
        return dnssec_hash_init(h, CH_DNSSEC_ALG_ECDSAP384SHA384, NULL, 0, NULL, 0);
    default:
        h->algorithm = 0;
        return CH_EINVAL;
    }
}

static void dnssec_hash_update(ch_dnssec_hash_priv *h, const uint8_t *p, size_t n) {
    if (hashes_sha1(h->algorithm)) {
        sha1_update(&h->state.sha1_state, p, n);
    } else if (hashes_sha512(h->algorithm)) {
        sha512_update(&h->state.sha512_state, p, n);
    } else {
        sha256_update(&h->state.sha256_state, p, n);
    }
}

static size_t dnssec_hash_final(ch_dnssec_hash_priv *h, uint8_t digest[CH_DNSSEC_DIGEST_MAX]) {
    size_t n = SHA256_LEN;
    if (hashes_sha1(h->algorithm)) {
        sha1_final(&h->state.sha1_state, digest);
        n = SHA1_LEN;
    } else if (h->algorithm == CH_DNSSEC_ALG_ECDSAP384SHA384) {
        sha384_final(&h->state.sha512_state, digest);
        n = SHA384_LEN;
    } else if (hashes_sha512(h->algorithm)) {
        sha512_final(&h->state.sha512_state, digest);
        n = SHA512_LEN;
    } else {
        sha256_final(&h->state.sha256_state, digest);
    }
    ct_wipe(h, sizeof *h);
    return n;
}

int ch_dnssec_verify(uint8_t algorithm, const uint8_t *key, size_t key_len, const uint8_t *digest,
                     size_t digest_len, const uint8_t *sig, size_t sig_len) {
    switch (algorithm) {
    case CH_DNSSEC_ALG_RSASHA256:
        if (digest_len != SHA256_LEN) {
            return CH_EINVAL;
        }
        return verify_rsa(key, key_len, digest, digest_len, sig, sig_len);
    case CH_DNSSEC_ALG_RSASHA512:
        if (digest_len != SHA512_LEN) {
            return CH_EINVAL;
        }
        return verify_rsa(key, key_len, digest, digest_len, sig, sig_len);
    case CH_DNSSEC_ALG_ECDSAP256SHA256:
        if (digest_len != SHA256_LEN || key_len != 64) {
            return CH_EINVAL;
        }
        if (sig_len != 64) {
            return CH_EAUTH;
        }
        return p256_ecdsa_verify_raw(key, digest, sig) ? CH_OK : CH_EAUTH;
    case CH_DNSSEC_ALG_ECDSAP384SHA384:
        if (digest_len != SHA384_LEN || key_len != 96) {
            return CH_EINVAL;
        }
        if (sig_len != 96) {
            return CH_EAUTH;
        }
        return p384_ecdsa_verify_raw(key, digest, sig) ? CH_OK : CH_EAUTH;
    case CH_DNSSEC_ALG_ED25519:
        if (digest_len != SHA512_LEN || key_len != 32) {
            return CH_EINVAL;
        }
        if (sig_len != 64) {
            return CH_EAUTH;
        }
        return ed25519_verify_hram(key, digest, sig) ? CH_OK : CH_EAUTH;
    default:
        return CH_EINVAL;
    }
}

// The public calls: each converts the caller's storage once (dnssec_hash.h).
int ch_dnssec_hash_init(ch_dnssec_hash *h, uint8_t algorithm, const uint8_t *key, size_t key_len,
                        const uint8_t *sig, size_t sig_len) {
    return dnssec_hash_init(dnssec_hash_priv(h), algorithm, key, key_len, sig, sig_len);
}

int ch_dnssec_digest_init(ch_dnssec_hash *h, uint8_t digest_type) {
    return dnssec_digest_init(dnssec_hash_priv(h), digest_type);
}

void ch_dnssec_hash_update(ch_dnssec_hash *h, const uint8_t *p, size_t n) {
    dnssec_hash_update(dnssec_hash_priv(h), p, n);
}

size_t ch_dnssec_hash_final(ch_dnssec_hash *h, uint8_t digest[CH_DNSSEC_DIGEST_MAX]) {
    return dnssec_hash_final(dnssec_hash_priv(h), digest);
}

#endif // CH_DNSSEC
