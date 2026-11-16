// The packet protection keys of RFC 9001 §5.1 and the key update of
// §6.1. quic_keys.h states the contract, including why the header
// protection key is written once and never updated.
//
// Every derivation here is one HKDF-Expand-Label over a traffic secret
// keysched.c already produced, with a zero-length context, which is
// what §5.1 specifies for all four labels (rfc9001.txt:1017-1021).
// QUIC reuses the TLS 1.3 key schedule, so the labels carry hkdf.c's
// "tls13 " prefix and nothing here builds an info string by hand. The
// four labels are the session's QUIC version's, which quic_version.h
// holds.
#include "quic_keys.h"

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING

#include <string.h>

#include "ch_assert.h"
#include "ct.h"
#include "hkdf.h"
#include "quic_version.h"
#ifdef CH_AES_STORED_SCHEDULE
#include "aes.h"
#include "gcm.h"
#endif

// The packet protection key and IV of §5.1 from one traffic secret, at
// hash_len and key_len, under the "quic key" and "quic iv" labels of
// version. quic_keys and quic_receive_keys hold the two alike.
static void derive_key_iv(uint32_t cpu, uint8_t *key, uint8_t *iv, uint32_t version,
                          const uint8_t *secret, size_t hash_len, size_t key_len) {
    (void)cpu; // a device object's HKDF takes no description of the CPU (hkdf.h)
    quic_labels labels = quic_version_labels(version);
    HKDF_EXPAND_LABEL_CPU(cpu, hash_len, secret, labels.key, NULL, 0, key, key_len);
    HKDF_EXPAND_LABEL_CPU(cpu, hash_len, secret, labels.iv, NULL, 0, iv, AEAD_NONCE);
}

// The next traffic secret of §6.1, written back over secret:
// secret' = HKDF-Expand-Label(secret, "quic ku", "", Hash.length), under
// the version's label. The new secret goes to a local first:
// hkdf_expand_label reads its secret argument while it writes out, so a
// derivation straight over the caller's buffer would read bytes this call
// had replaced.
static void next_secret(uint32_t cpu, uint8_t *secret, size_t hash_len, uint32_t version) {
    (void)cpu; // as in derive_key_iv
    uint8_t next[HKDF_HASH_MAX];
    HKDF_EXPAND_LABEL_CPU(cpu, hash_len, secret, quic_version_labels(version).ku, NULL, 0, next,
                          hash_len);
    memcpy(secret, next, hash_len);
    ct_wipe(next, sizeof next);
}

#ifdef CH_SUITE_AES_GCM
// The hash of a set's suite, the length of each secret it is derived from.
#define SET_HASH_LEN(set) suite_hash_len((set)->suite)

void quic_keys_init_suite(uint32_t cpu, quic_keys *k, uint32_t version, const uint8_t *secret,
                          uint16_t suite) {
    (void)cpu; // a device object's HKDF takes no description of the CPU (hkdf.h)
    CH_ASSERT(k != NULL);
    CH_ASSERT(secret != NULL);
    // The whole key array is written before the shorter derive, so an
    // AES-128 key leaves no bytes of the previous key behind it.
    ct_wipe(k->key, sizeof k->key);
    derive_key_iv(cpu, k->key, k->iv, version, secret, suite_hash_len(suite), suite_key_len(suite));
    k->suite = suite;
    k->sealed = 0;
#ifdef CH_AES_STORED_SCHEDULE
    // The schedule of the key just derived and the powers of its hash
    // subkey, or zero under ChaCha20, so neither of the previous key
    // stays behind (suite.h).
    ct_wipe(k->schedule, sizeof k->schedule);
    ct_wipe(k->ghash_powers, sizeof k->ghash_powers);
    k->stored = 0;
    if (suite_runs_aes_gcm(suite)) {
        k->stored = (uint8_t)gcm_traffic_key_store(k->schedule, k->ghash_powers, cpu, k->key,
                                                   suite_key_len(suite));
    }
#else
    k->stored = 0;
#endif
}

void quic_hp_key_init_suite(uint32_t cpu, quic_hp_key *h, uint32_t version, const uint8_t *secret,
                            uint16_t suite) {
    (void)cpu; // as in quic_keys_init_suite
    CH_ASSERT(h != NULL);
    CH_ASSERT(secret != NULL);
    ct_wipe(h->key, sizeof h->key);
    HKDF_EXPAND_LABEL_CPU(cpu, suite_hash_len(suite), secret, quic_version_labels(version).hp, NULL,
                          0, h->key, suite_key_len(suite));
    h->suite = suite;
#ifdef CH_AES_STORED_SCHEDULE
    ct_wipe(h->schedule, sizeof h->schedule);
    h->stored = 0;
    if (suite_runs_aes_gcm(suite)) {
        h->stored = (uint8_t)aes_traffic_key_store(h->schedule, cpu, h->key, suite_key_len(suite));
    }
#endif
}

void quic_receive_keys_init_suite(uint32_t cpu, quic_receive_keys *r, uint32_t version,
                                  const uint8_t *secret, uint16_t suite) {
    CH_ASSERT(r != NULL);
    CH_ASSERT(secret != NULL);
    // As in quic_keys_init_suite: an AES-128 key leaves no bytes of the
    // previous key behind it. r holds no schedule and no powers to write.
    ct_wipe(r->key, sizeof r->key);
    derive_key_iv(cpu, r->key, r->iv, version, secret, suite_hash_len(suite), suite_key_len(suite));
    r->suite = suite;
}

void quic_keys_init(uint32_t cpu, quic_keys *k, uint32_t version,
                    const uint8_t secret[SHA256_LEN]) {
    quic_keys_init_suite(cpu, k, version, secret, SUITE_CHACHA20_POLY1305_SHA256);
}

void quic_receive_keys_init(uint32_t cpu, quic_receive_keys *r, uint32_t version,
                            const uint8_t secret[SHA256_LEN]) {
    quic_receive_keys_init_suite(cpu, r, version, secret, SUITE_CHACHA20_POLY1305_SHA256);
}

void quic_hp_key_init(uint32_t cpu, quic_hp_key *h, uint32_t version,
                      const uint8_t secret[SHA256_LEN]) {
    quic_hp_key_init_suite(cpu, h, version, secret, SUITE_CHACHA20_POLY1305_SHA256);
}
#else
// A build with one suite derives every secret at SHA-256.
#define SET_HASH_LEN(set) SHA256_LEN

void quic_keys_init(uint32_t cpu, quic_keys *k, uint32_t version,
                    const uint8_t secret[SHA256_LEN]) {
    CH_ASSERT(k != NULL);
    CH_ASSERT(secret != NULL);
    derive_key_iv(cpu, k->key, k->iv, version, secret, SHA256_LEN, AEAD_KEY);
}

void quic_receive_keys_init(uint32_t cpu, quic_receive_keys *r, uint32_t version,
                            const uint8_t secret[SHA256_LEN]) {
    CH_ASSERT(r != NULL);
    CH_ASSERT(secret != NULL);
    derive_key_iv(cpu, r->key, r->iv, version, secret, SHA256_LEN, AEAD_KEY);
}

void quic_hp_key_init(uint32_t cpu, quic_hp_key *h, uint32_t version,
                      const uint8_t secret[SHA256_LEN]) {
    (void)cpu; // as in quic_keys_init
    CH_ASSERT(h != NULL);
    CH_ASSERT(secret != NULL);
    HKDF_EXPAND_LABEL_CPU(cpu, SHA256_LEN, secret, quic_version_labels(version).hp, NULL, 0, h->key,
                          CHACHA20_KEY);
}
#endif

void quic_keys_update(uint32_t cpu, uint8_t *secret, quic_keys *k, uint32_t version) {
    CH_ASSERT(secret != NULL);
    CH_ASSERT(k != NULL);
    next_secret(cpu, secret, SET_HASH_LEN(k), version);
    // §6.1 updates the packet protection key and IV and nothing else;
    // no quic_hp_key is in scope here, which is the type system holding
    // that rule rather than a comment. The AEAD stays the set's own.
    QUIC_KEYS_INIT_SUITE(cpu, k, version, secret, k->suite);
}

void quic_receive_keys_update(uint32_t cpu, uint8_t *secret, quic_receive_keys *r,
                              uint32_t version) {
    CH_ASSERT(secret != NULL);
    CH_ASSERT(r != NULL);
    next_secret(cpu, secret, SET_HASH_LEN(r), version);
    // As in quic_keys_update: the key and the IV alone, under r's suite.
    QUIC_RECEIVE_KEYS_INIT_SUITE(cpu, r, version, secret, r->suite);
}

#endif // CH_TRANSPORT_QUIC_NONBLOCKING
