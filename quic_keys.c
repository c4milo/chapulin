// The packet protection keys of RFC 9001 §5.1 and the key update of
// §6.1. quic_keys.h states the contract, including why the header
// protection key is written once and never updated.
//
// Every derivation here is one HKDF-Expand-Label over a traffic secret
// keysched.c already produced, with a zero-length context, which is
// what §5.1 specifies for all four labels (rfc9001.txt:1017-1021).
// QUIC reuses the TLS 1.3 key schedule, so the labels carry hkdf.c's
// "tls13 " prefix and nothing here builds an info string by hand.
#include "quic_keys.h"

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING

#include <string.h>

#include "ch_assert.h"
#include "ct.h"
#include "hkdf.h"

#ifdef CH_SUITE_AES_GCM
void quic_keys_init_suite(quic_keys *k, const uint8_t *secret, uint16_t suite) {
    CH_ASSERT(k != NULL);
    CH_ASSERT(secret != NULL);
    // The whole key array is written before the shorter derive, so an
    // AES-128 key leaves no bytes of the previous key behind it.
    ct_wipe(k->key, sizeof k->key);
    size_t hash_len = suite_hash_len(suite);
    hkdf_expand_label(hash_len, secret, "quic key", NULL, 0, k->key, suite_key_len(suite));
    hkdf_expand_label(hash_len, secret, "quic iv", NULL, 0, k->iv, AEAD_NONCE);
    k->suite = suite;
    k->sealed = 0;
}

void quic_hp_key_init_suite(quic_hp_key *h, const uint8_t *secret, uint16_t suite) {
    CH_ASSERT(h != NULL);
    CH_ASSERT(secret != NULL);
    ct_wipe(h->key, sizeof h->key);
    hkdf_expand_label(suite_hash_len(suite), secret, "quic hp", NULL, 0, h->key,
                      suite_key_len(suite));
    h->suite = suite;
}

void quic_keys_init(quic_keys *k, const uint8_t secret[SHA256_LEN]) {
    quic_keys_init_suite(k, secret, SUITE_CHACHA20_POLY1305_SHA256);
}

void quic_hp_key_init(quic_hp_key *h, const uint8_t secret[SHA256_LEN]) {
    quic_hp_key_init_suite(h, secret, SUITE_CHACHA20_POLY1305_SHA256);
}
#else
void quic_keys_init(quic_keys *k, const uint8_t secret[SHA256_LEN]) {
    CH_ASSERT(k != NULL);
    CH_ASSERT(secret != NULL);
    hkdf_expand_label(SHA256_LEN, secret, "quic key", NULL, 0, k->key, AEAD_KEY);
    hkdf_expand_label(SHA256_LEN, secret, "quic iv", NULL, 0, k->iv, AEAD_NONCE);
}

void quic_hp_key_init(quic_hp_key *h, const uint8_t secret[SHA256_LEN]) {
    CH_ASSERT(h != NULL);
    CH_ASSERT(secret != NULL);
    hkdf_expand_label(SHA256_LEN, secret, "quic hp", NULL, 0, h->key, CHACHA20_KEY);
}
#endif

void quic_keys_update(uint8_t *secret, quic_keys *k) {
    CH_ASSERT(secret != NULL);
    CH_ASSERT(k != NULL);
#ifdef CH_SUITE_AES_GCM
    size_t hash_len = suite_hash_len(k->suite);
#else
    size_t hash_len = SHA256_LEN;
#endif
    // secret' = HKDF-Expand-Label(secret, "quic ku", "", Hash.length).
    // The new secret goes to a local first: hkdf_expand_label reads its
    // secret argument while it writes out, so deriving straight over
    // the caller's buffer would read bytes this call had replaced.
    uint8_t next[HKDF_HASH_MAX];
    hkdf_expand_label(hash_len, secret, "quic ku", NULL, 0, next, hash_len);
    memcpy(secret, next, hash_len);
    ct_wipe(next, sizeof next);
    // §6.1 updates the packet protection key and IV and nothing else;
    // no quic_hp_key is in scope here, which is the type system holding
    // that rule rather than a comment. The AEAD stays the set's own.
    QUIC_KEYS_INIT_SUITE(k, secret, k->suite);
}

#endif // CH_TRANSPORT_QUIC_NONBLOCKING
