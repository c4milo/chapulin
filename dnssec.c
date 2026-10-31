// The DNSSEC hash and signature check. dnssec.h states the contract.
// This file reads the DNSKEY's key field and picks the hash and the
// verifier; the verifiers are rsa_pkcs1.c's and p256.c's. Outside a
// DNSSEC build it holds nothing, and dnssec.h's hash headers keep the
// unit from being empty.
#include "dnssec.h"

#ifdef CH_DNSSEC

#include "buf.h"
#include "ct.h"
#include "ed25519_verify.h"
#include "p256.h"
#include "rsa.h"
#include "rsa_pkcs1.h"
#include "sha256.h"
#include "sha512.h"

// An RSA key field, RFC 3110 section 2: a one-byte exponent length, or a
// zero byte and a two-byte one, then the exponent, then the modulus,
// which runs to the end of the field.
typedef struct {
    uint64_t e;
    const uint8_t *n;
    size_t n_len;
} rsa_key;

// Reads key into k. Returns 0 for a field it refuses: an exponent of 0
// bytes, or longer than CH_DNSSEC_RSA_EXPONENT_MAX, or that begins with a
// zero byte; a modulus of 0 bytes or that begins with a zero byte.
static int read_rsa_key(const uint8_t *key, size_t key_len, rsa_key *k) {
    rbuf rb;
    rb_init(&rb, key, key_len);
    size_t e_len = rb_u8(&rb);
    if (e_len == 0) {
        e_len = rb_u16(&rb);
    }
    const uint8_t *e = rb_bytes(&rb, e_len);
    if (rb.err || e_len == 0 || e_len > CH_DNSSEC_RSA_EXPONENT_MAX || e[0] == 0) {
        return 0;
    }
    k->e = 0;
    for (size_t i = 0; i < e_len; i++) {
        k->e = (k->e << 8) | e[i];
    }
    // The modulus runs to the end of the field, so the reader ends empty
    // (INV-25).
    k->n_len = rb_left(&rb);
    k->n = rb_bytes(&rb, k->n_len);
    return !rb.err && rb_left(&rb) == 0 && k->n_len != 0 && k->n[0] != 0;
}

static int verify_rsa(const uint8_t *key, size_t key_len, const uint8_t *digest, size_t digest_len,
                      const uint8_t *sig, size_t sig_len) {
    rsa_key k;
    if (!read_rsa_key(key, key_len, &k) || k.e < 3 || (k.e & 1) == 0 ||
        k.n_len < CH_DNSSEC_RSA_MODULUS_MIN || k.n_len > CH_RSA_MODULUS_MAX ||
        (k.n[k.n_len - 1] & 1) == 0) {
        return CH_EINVAL;
    }
    return rsa_pkcs1_verify_exponent(k.n, k.n_len, k.e, digest, digest_len, sig, sig_len)
               ? CH_OK
               : CH_EAUTH;
}

// 1 for the algorithms whose hash is SHA-512.
static int hashes_sha512(uint8_t algorithm) {
    return algorithm == CH_DNSSEC_ALG_RSASHA512 || algorithm == CH_DNSSEC_ALG_ED25519;
}

int ch_dnssec_hash_init(ch_dnssec_hash *h, uint8_t algorithm, const uint8_t *key, size_t key_len,
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

void ch_dnssec_hash_update(ch_dnssec_hash *h, const uint8_t *p, size_t n) {
    if (hashes_sha512(h->algorithm)) {
        sha512_update(&h->state.sha512_state, p, n);
    } else {
        sha256_update(&h->state.sha256_state, p, n);
    }
}

size_t ch_dnssec_hash_final(ch_dnssec_hash *h, uint8_t digest[CH_DNSSEC_DIGEST_MAX]) {
    size_t n = SHA256_LEN;
    if (hashes_sha512(h->algorithm)) {
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

#endif // CH_DNSSEC
