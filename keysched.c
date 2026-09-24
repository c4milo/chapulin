#include "keysched.h"

#include "ct.h"
#include "hkdf.h"
#include "sha256.h"

// SHA256("") — the transcript hash of the empty context.
static const uint8_t empty_hash_sha256[SHA256_LEN] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

#ifdef CH_HASH_SHA384
// SHA384("") — the same for a SHA-384 suite.
static const uint8_t empty_hash_sha384[SHA384_LEN] = {
    0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
    0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
    0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b};
#endif

// The empty transcript's hash under the hash hash_len names. hash_len is
// public, so the branch is too.
static const uint8_t *empty_hash(size_t hash_len) {
#ifdef CH_HASH_SHA384
    if (hash_len == SHA384_LEN) {
        return empty_hash_sha384;
    }
#else
    (void)hash_len;
#endif
    return empty_hash_sha256;
}

// Hash.length zero bytes: the salt of the early secret and the input of
// the master secret (rfc9846.txt:4182-4185), read at hash_len.
static const uint8_t zeros[HKDF_HASH_MAX] = {0};

void ks_early(size_t hash_len, const uint8_t *psk, size_t psk_len, int resumption, uint8_t *early,
              uint8_t *binder_key) {
    hkdf_extract(hash_len, zeros, hash_len, psk, psk_len, early);
    hkdf_derive_secret(hash_len, early, resumption ? "res binder" : "ext binder",
                       empty_hash(hash_len), binder_key);
}

void ks_verify_data(size_t hash_len, const uint8_t *key, const uint8_t *transcript, uint8_t *out) {
    uint8_t finished_key[HKDF_HASH_MAX];
    hkdf_expand_label(hash_len, key, "finished", NULL, 0, finished_key, hash_len);
    hmac(hash_len, finished_key, hash_len, transcript, hash_len, out);
    ct_wipe(finished_key, sizeof finished_key);
}

void ks_handshake(size_t hash_len, const uint8_t *early, const uint8_t *ecdhe, size_t ecdhe_len,
                  const uint8_t *transcript, uint8_t *handshake_secret, uint8_t *c_hs,
                  uint8_t *s_hs) {
    uint8_t derived[HKDF_HASH_MAX];
    hkdf_derive_secret(hash_len, early, "derived", empty_hash(hash_len), derived);
    hkdf_extract(hash_len, derived, hash_len, ecdhe, ecdhe_len, handshake_secret);
    hkdf_derive_secret(hash_len, handshake_secret, "c hs traffic", transcript, c_hs);
    hkdf_derive_secret(hash_len, handshake_secret, "s hs traffic", transcript, s_hs);
    ct_wipe(derived, sizeof derived);
}

void ks_master(size_t hash_len, const uint8_t *handshake_secret, const uint8_t *transcript,
               uint8_t *master, uint8_t *c_ap, uint8_t *s_ap) {
    uint8_t derived[HKDF_HASH_MAX];
    hkdf_derive_secret(hash_len, handshake_secret, "derived", empty_hash(hash_len), derived);
    hkdf_extract(hash_len, derived, hash_len, zeros, hash_len, master);
    hkdf_derive_secret(hash_len, master, "c ap traffic", transcript, c_ap);
    hkdf_derive_secret(hash_len, master, "s ap traffic", transcript, s_ap);
    ct_wipe(derived, sizeof derived);
}

void ks_res_master(size_t hash_len, const uint8_t *master, const uint8_t *transcript,
                   uint8_t *res_master) {
    hkdf_derive_secret(hash_len, master, "res master", transcript, res_master);
}

void ks_res_psk(size_t hash_len, const uint8_t *res_master, const uint8_t *nonce, size_t nonce_len,
                uint8_t *psk) {
    hkdf_expand_label(hash_len, res_master, "resumption", nonce, nonce_len, psk, hash_len);
}

#ifdef CH_EXPORTER
void ks_exp_master(size_t hash_len, const uint8_t *master, const uint8_t *transcript,
                   uint8_t *exp_master) {
    hkdf_derive_secret(hash_len, master, "exp master", transcript, exp_master);
}

// Hash(context) at hash_len, into hashed.
static void hash_context(size_t hash_len, const uint8_t *context, size_t context_len,
                         uint8_t *hashed) {
#ifdef CH_HASH_SHA384
    if (hash_len == SHA384_LEN) {
        sha384_of(context, context_len, hashed);
        return;
    }
#else
    (void)hash_len;
#endif
    sha256_of(context, context_len, hashed);
}

void ks_exporter(size_t hash_len, const uint8_t *exp_master, const char *label,
                 const uint8_t *context, size_t context_len, uint8_t *out, size_t out_len) {
    uint8_t derived[HKDF_HASH_MAX];
    hkdf_derive_secret(hash_len, exp_master, label, empty_hash(hash_len), derived);
    // Hash("") is the constant above, so an empty context needs no call
    // and raises no question about a NULL pointer with a zero length.
    uint8_t hashed[HKDF_HASH_MAX];
    const uint8_t *context_hash = empty_hash(hash_len);
    if (context_len != 0) {
        hash_context(hash_len, context, context_len, hashed);
        context_hash = hashed;
    }
    hkdf_expand_label(hash_len, derived, "exporter", context_hash, hash_len, out, out_len);
    ct_wipe(derived, sizeof derived);
}
#endif
