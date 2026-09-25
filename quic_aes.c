// The two aes_public_key constructors and the two forward-cipher entries
// that take one. quic_aes.h states every contract; this file implements
// them and nothing else.
//
// No cipher here. The Makefile AES variable picks the one source that
// implements the key expansion and the block cipher — quic_aes_soft.c,
// quic_aes_hw.c or quic_aes_extern.c — and quic_aes_block.h states the
// contract all three meet. This file derives the RFC 9001 keys, owns the
// aes_public_key, and hands round keys down as bytes.
//
// Which keys may arrive here is INV-26 in docs/invariants.md: the
// Initial keys, which anyone who sees a Destination Connection ID can
// derive (RFC 9001 §5.2), the header protection key derived from the
// same secret (§5.1), and the Retry key the RFC prints (§5.8). No key
// from the TLS key schedule reaches this file. That bound holds under
// every AES choice, and it is what an AES=soft build needs, because that
// implementation's S-box is a table indexed with cipher state.
#include "quic_aes.h"

#if defined(CH_TRANSPORT_QUIC) || defined(CH_SUITE_AES_GCM)

#include <string.h>

#include "hkdf.h"
#include "quic_aes_block.h"
#include "quic_aes_key.h"
#ifdef CH_SUITE_AES_GCM
#include "aes_traffic_key.h"
#include "ch_assert.h"
#endif

// RFC 9001 §5.2's printed salt, the input every Initial secret starts
// from (rfc9001.txt:1051-1055, rfc9001.txt:1066).
#ifdef CH_TRANSPORT_QUIC
static const uint8_t INITIAL_SALT[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34,
                                         0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                                         0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};

// RFC 9001 §5.8's printed Retry integrity tag key, 0xbe0c690b9f66575a1d766b54e368c84e
// (rfc9001.txt:1499-1500).
static const uint8_t RETRY_KEY[AES_128_KEY] = {0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
                                               0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e};
#endif // CH_TRANSPORT_QUIC

#ifdef CH_TRANSPORT_QUIC
// The three entries below are QUIC's alone: two build a key from what RFC
// 9001 fixes for Initial and Retry packets, and the third is header
// protection, which a TLS record does not have. A suite build compiles
// the cipher above and none of this.
int aes_public_key_initial(aes_public_key *k, const uint8_t *dcid, size_t dcid_len,
                           uint8_t endpoint) {
    if (dcid_len > CH_QUIC_DCID_MAX) {
        return CH_EINVAL;
    }
    if (endpoint != CH_QUIC_ENDPOINT_CLIENT && endpoint != CH_QUIC_ENDPOINT_SERVER) {
        return CH_EINVAL;
    }
    // RFC 9001 §5.2: the salt and the Destination Connection ID extract
    // one secret, and one label per endpoint expands it
    // (rfc9001.txt:1057-1061). Which endpoint a caller asks for is the
    // caller's; this file reads no role and derives what it is given.
    uint8_t initial_secret[SHA256_LEN];
    hkdf_extract(SHA256_LEN, INITIAL_SALT, sizeof INITIAL_SALT, dcid, dcid_len, initial_secret);
    const char *label = endpoint == CH_QUIC_ENDPOINT_CLIENT ? "client in" : "server in";
    // RFC 9001 §5.2 names this one client_initial_secret or
    // server_initial_secret, one per endpoint.
    uint8_t direction_secret[SHA256_LEN];
    hkdf_expand_label(SHA256_LEN, initial_secret, label, NULL, 0, direction_secret,
                      sizeof direction_secret);
    // RFC 9001 §5.1: three labels over that secret, each with a
    // zero-length context (rfc9001.txt:1029-1032).
    uint8_t key[AES_128_KEY];
    hkdf_expand_label(SHA256_LEN, direction_secret, "quic key", NULL, 0, key, sizeof key);
    aes_expand_round_keys(key, k->key.round_keys);
    hkdf_expand_label(SHA256_LEN, direction_secret, "quic iv", NULL, 0, k->iv, sizeof k->iv);
    hkdf_expand_label(SHA256_LEN, direction_secret, "quic hp", NULL, 0, key, sizeof key);
    aes_expand_round_keys(key, k->hp.round_keys);
#ifdef CH_AES_256
    // RFC 9001 §5.2 fixes AES-128 for the Initial level whatever suite
    // TLS goes on to negotiate.
    k->key.rounds = AES_128_ROUNDS;
    k->hp.rounds = AES_128_ROUNDS;
#endif
    // No wipe of initial_secret, direction_secret or key. Every byte of
    // the three is public: RFC 9001 §5 says so of the Initial keys
    // (rfc9001.txt:999-1001), and this constructor derives nothing else.
    // It is the one AES entry never passed a secret key, because a
    // -DCH_SUITE_AES_GCM build takes its key from keysched.c and not from
    // here, so the wipes quic_gcm.c and the block implementations carry
    // would say something false in this frame. INV-26 states which entry
    // holds which rule.
    return CH_OK;
}

void aes_public_key_retry(aes_public_key *k) {
    aes_expand_round_keys(RETRY_KEY, k->key.round_keys);
#ifdef CH_AES_256
    k->key.rounds = AES_128_ROUNDS;
#endif
    // RFC 9001 §5.8 prints the nonce the caller passes to gcm_seal, and
    // a Retry packet carries no header protection, so both fields stay
    // zero rather than holding a key this call did not derive.
    memset(k->iv, 0, sizeof k->iv);
    memset(&k->hp, 0, sizeof k->hp);
}
#endif // CH_TRANSPORT_QUIC

void aes_encrypt_schedule(const aes_key_schedule *s, const uint8_t in[AES_BLOCK],
                          uint8_t out[AES_BLOCK]) {
#ifdef CH_AES_256
    // The round count is the suite's, so this branch reads a public
    // value.
    if (s->rounds == AES_256_ROUNDS) {
        aes_cipher_block_256(s->round_keys, in, out);
        return;
    }
#endif
    aes_cipher_block(s->round_keys, in, out);
}

void aes_encrypt_block(const aes_public_key *k, const uint8_t in[AES_BLOCK],
                       uint8_t out[AES_BLOCK]) {
    aes_encrypt_schedule(&k->key, in, out);
}

#ifdef CH_TRANSPORT_QUIC
void aes_encrypt_block_hp(const aes_public_key *k, const uint8_t sample[AES_BLOCK],
                          uint8_t out[AES_BLOCK]) {
    aes_cipher_block(k->hp.round_keys, sample, out);
}

#endif // CH_TRANSPORT_QUIC

#ifdef CH_SUITE_AES_GCM
void aes_traffic_key_init(aes_traffic_key *k, const uint8_t *key, size_t key_len) {
    CH_ASSERT(key_len == AES_128_KEY || key_len == AES_256_KEY);
    // key_len is the suite's, which the ServerHello named in the clear,
    // so the branch reads a public value. The key itself goes to the AES
    // instructions alone: ct.h refuses this build without AES=hw.
    if (key_len == AES_256_KEY) {
        aes_expand_round_keys_256(key, k->key.round_keys);
        k->key.rounds = AES_256_ROUNDS;
        return;
    }
    aes_expand_round_keys(key, k->key.round_keys);
    k->key.rounds = AES_128_ROUNDS;
}

#ifdef CH_TRANSPORT_QUIC
void aes_traffic_encrypt_block(const aes_traffic_key *k, const uint8_t in[AES_BLOCK],
                               uint8_t out[AES_BLOCK]) {
    aes_encrypt_schedule(&k->key, in, out);
}
#endif
#endif // CH_SUITE_AES_GCM

#endif // CH_TRANSPORT_QUIC || CH_SUITE_AES_GCM
