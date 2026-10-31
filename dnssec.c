// The DNSSEC signature check. dnssec.h states the contract. This file
// reads the DNSKEY's key field and picks the verifier; the verifiers are
// rsa_pkcs1.c's and p256.c's.
#include "dnssec.h"

// Outside a DNSSEC build this file holds nothing, and the header below
// declares what every build declares, so the unit is not empty.
#include "tls.h"

#ifdef CH_DNSSEC

#include "buf.h"
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
// bytes, or longer than DNSSEC_RSA_EXPONENT_MAX, or that begins with a
// zero byte; a modulus of 0 bytes or that begins with a zero byte.
static int read_rsa_key(const uint8_t *key, size_t key_len, rsa_key *k) {
    rbuf rb;
    rb_init(&rb, key, key_len);
    size_t e_len = rb_u8(&rb);
    if (e_len == 0) {
        e_len = rb_u16(&rb);
    }
    const uint8_t *e = rb_bytes(&rb, e_len);
    if (rb.err || e_len == 0 || e_len > DNSSEC_RSA_EXPONENT_MAX || e[0] == 0) {
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
        k.n_len < DNSSEC_RSA_MODULUS_MIN || k.n_len > CH_RSA_MODULUS_MAX ||
        (k.n[k.n_len - 1] & 1) == 0) {
        return CH_EINVAL;
    }
    return rsa_pkcs1_verify_exponent(k.n, k.n_len, k.e, digest, digest_len, sig, sig_len)
               ? CH_OK
               : CH_EAUTH;
}

int dnssec_verify(uint8_t algorithm, const uint8_t *key, size_t key_len, const uint8_t *digest,
                  size_t digest_len, const uint8_t *sig, size_t sig_len) {
    switch (algorithm) {
    case DNSSEC_ALG_RSASHA256:
        if (digest_len != SHA256_LEN) {
            return CH_EINVAL;
        }
        return verify_rsa(key, key_len, digest, digest_len, sig, sig_len);
    case DNSSEC_ALG_RSASHA512:
        if (digest_len != SHA512_LEN) {
            return CH_EINVAL;
        }
        return verify_rsa(key, key_len, digest, digest_len, sig, sig_len);
    case DNSSEC_ALG_ECDSAP256SHA256:
        if (digest_len != SHA256_LEN || key_len != 64) {
            return CH_EINVAL;
        }
        if (sig_len != 64) {
            return CH_EAUTH;
        }
        return p256_ecdsa_verify_raw(key, digest, sig) ? CH_OK : CH_EAUTH;
    default:
        return CH_EINVAL;
    }
}

#endif // CH_DNSSEC
