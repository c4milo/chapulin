// The two aes_public_key constructors and the two forward-cipher entries
// that take one. aes.h states every contract; this file implements
// them and nothing else.
//
// No cipher here. The Makefile AES variable picks the one source that
// implements the key expansion and the block cipher — quic_aes_soft.c,
// aes_hw.c or aes_extern.c — and aes_block.h states the
// contract all three meet. This file derives the RFC 9001 keys, owns the
// aes_public_key, and hands round keys down as bytes. An AES=runtime QUIC
// object holds two of them, aes_hw.c and quic_aes_soft.c, and this file
// is where a key is put on one: the caller's probe result picks for an
// Initial key, the table runs the Retry key, and the instructions run
// every traffic key (CH_AES_TWO_CIPHERS, aes.h).
//
// Which keys may arrive here is INV-26 in docs/invariants.md: the
// Initial keys, which anyone who sees a Destination Connection ID can
// derive (RFC 9001 §5.2), the header protection key derived from the
// same secret (§5.1), and the Retry key the RFC prints (§5.8), each in
// QUIC version 1 and in version 2, whose salt and Retry key RFC 9369
// prints too (§3.3.1, §3.3.3). No key from the TLS key schedule is passed
// to this file. That bound holds under every AES choice, and it is what an
// AES=soft build needs, because that implementation's S-box is a table
// indexed with cipher state.
#include "aes.h"

#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)

#include <string.h>

#include "aes_block.h"
#include "aes_public_key.h"
#include "hkdf.h"
#ifdef CH_SUITE_AES_GCM
#include "aes_traffic_key.h"
#endif
#if defined(CH_SUITE_AES_GCM) || defined(CH_AES_TWO_CIPHERS)
#include "ch_assert.h"
#endif
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#include "quic_version.h"
#endif

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
// The length of an Initial salt, 20 bytes in both QUIC versions RFC 9001 and
// RFC 9369 define (rfc9001.txt:1066, rfc9369.txt:163-165).
#define INITIAL_SALT_LEN 20

// RFC 9001 §5.2's printed salt for QUIC version 1, the input every version 1
// Initial secret starts from (rfc9001.txt:1051-1055, rfc9001.txt:1066).
static const uint8_t INITIAL_SALT_V1[INITIAL_SALT_LEN] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34,
                                                          0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                                                          0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};

// RFC 9369 §3.3.1's printed salt for QUIC version 2,
// 0x0dede3def700a6db819381be6e269dcbf9bd2ed9, the input every version 2
// Initial secret starts from (rfc9369.txt:158-165).
static const uint8_t INITIAL_SALT_V2[INITIAL_SALT_LEN] = {0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6,
                                                          0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26,
                                                          0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9};

// RFC 9001 §5.8's printed Retry integrity tag key for QUIC version 1,
// 0xbe0c690b9f66575a1d766b54e368c84e (rfc9001.txt:1499-1500).
static const uint8_t RETRY_KEY_V1[AES_128_KEY] = {0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
                                                  0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e};

// RFC 9369 §3.3.3's printed Retry integrity tag key for QUIC version 2,
// 0x8fb4b01b56ac48e260fbcbcead7ccc92 (rfc9369.txt:176-188).
static const uint8_t RETRY_KEY_V2[AES_128_KEY] = {0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
                                                  0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92};

// Each version's salt and Retry key, at the index quic_version_index gives
// it: version 1's first, version 2's second.
static const uint8_t *const INITIAL_SALTS[QUIC_VERSION_COUNT] = {INITIAL_SALT_V1, INITIAL_SALT_V2};
static const uint8_t *const RETRY_KEYS[QUIC_VERSION_COUNT] = {RETRY_KEY_V1, RETRY_KEY_V2};

// The salt version's Initial secrets start from, and the key its Retry
// integrity tag is sealed under. version is one quic_version_derived admits,
// because quic_initial.c and quic_retry.c refuse every other version before
// they call here. Each is a table read rather than a comparison, for the
// reason quic_version_index states: this file's conditional branches are a
// count the Makefile's BRANCH_CEILING records.
static const uint8_t *initial_salt(uint32_t version) {
    return INITIAL_SALTS[quic_version_index(version)];
}

static const uint8_t *retry_key(uint32_t version) {
    return RETRY_KEYS[quic_version_index(version)];
}
#endif // CH_TRANSPORT_QUIC_NONBLOCKING

#ifdef CH_AES_TWO_CIPHERS
// Whether s runs on the AES instructions rather than on the table. The
// value is the caller's probe result for an Initial key, the table's for
// the Retry key and the instructions' for every traffic key
// (aes_schedule.h), so the branch on it reads a public value.
static int on_instructions(const aes_key_schedule *s) {
    return s->instructions == CH_AES_INSTRUCTIONS_PRESENT;
}

// FIPS 197 §5.2 for one public AES-128 key into s: on the instructions when
// aes_instructions is CH_AES_INSTRUCTIONS_PRESENT and on the table for any
// other value, and s records which. The key is public, so the table leaks
// nothing (INV-26), and a CPU without the instructions runs none here.
static void expand_public_key(aes_key_schedule *s, const uint8_t key[AES_128_KEY],
                              uint8_t aes_instructions) {
    if (aes_instructions == CH_AES_INSTRUCTIONS_PRESENT) {
        s->instructions = CH_AES_INSTRUCTIONS_PRESENT;
        aes_expand_round_keys(key, s->round_keys);
        return;
    }
    s->instructions = CH_AES_INSTRUCTIONS_ABSENT;
    aes_soft_expand_round_keys(key, s->round_keys);
}
#endif // CH_AES_TWO_CIPHERS

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
// RFC 9001 §5.2 for one endpoint, up to the key expansion: the packet
// protection key into key, the IV into iv and the header protection key
// into hp. Returns CH_EINVAL and writes nothing when dcid_len is above
// CH_QUIC_DCID_MAX or endpoint is neither of aes.h's two names, and CH_OK
// once all three are written. Both aes_public_key_initial entries below
// call it, and each expands key and hp the way its build runs AES.
static int derive_initial(uint8_t key[AES_128_KEY], uint8_t iv[AES_IV], uint8_t hp[AES_128_KEY],
                          uint32_t version, const uint8_t *dcid, size_t dcid_len,
                          uint8_t endpoint) {
    if (dcid_len > CH_QUIC_DCID_MAX) {
        return CH_EINVAL;
    }
    if (endpoint != CH_QUIC_ENDPOINT_CLIENT && endpoint != CH_QUIC_ENDPOINT_SERVER) {
        return CH_EINVAL;
    }
    // RFC 9001 §5.2: the version's salt and the Destination Connection ID
    // extract one secret, and one label per endpoint expands it
    // (rfc9001.txt:1057-1061). Which endpoint a caller asks for is the
    // caller's; this file reads no role and derives what it is given.
    uint8_t initial_secret[SHA256_LEN];
    hkdf_extract(SHA256_LEN, initial_salt(version), INITIAL_SALT_LEN, dcid, dcid_len,
                 initial_secret);
    const char *label = endpoint == CH_QUIC_ENDPOINT_CLIENT ? "client in" : "server in";
    // RFC 9001 §5.2 names this one client_initial_secret or
    // server_initial_secret, one per endpoint.
    uint8_t direction_secret[SHA256_LEN];
    hkdf_expand_label(SHA256_LEN, initial_secret, label, NULL, 0, direction_secret,
                      sizeof direction_secret);
    // RFC 9001 §5.1: the version's three labels over that secret, each
    // with a zero-length context (rfc9001.txt:1029-1032).
    quic_labels labels = quic_version_labels(version);
    hkdf_expand_label(SHA256_LEN, direction_secret, labels.key, NULL, 0, key, AES_128_KEY);
    hkdf_expand_label(SHA256_LEN, direction_secret, labels.iv, NULL, 0, iv, AES_IV);
    hkdf_expand_label(SHA256_LEN, direction_secret, labels.hp, NULL, 0, hp, AES_128_KEY);
    // No wipe of initial_secret or direction_secret, and none of key and
    // hp in the entries below. Every byte of them is public: RFC 9001 §5
    // says so of the Initial keys (rfc9001.txt:999-1001), and this
    // derivation produces nothing else. It is the one AES entry never
    // passed a secret key, because a -DCH_SUITE_AES_GCM build takes its key
    // from keysched.c and not from here, so the wipes gcm.c and the block
    // implementations carry would say something false in this frame.
    // INV-26 states which entry holds which rule.
    return CH_OK;
}

// RFC 9001 §5.2 fixes AES-128 for the Initial level whatever suite TLS
// goes on to negotiate, so a build with AES-256 records ten rounds in
// both schedules of an Initial key.
static void initial_rounds(aes_public_key *k) {
#ifdef CH_AES_256
    k->key.rounds = AES_128_ROUNDS;
    k->hp.rounds = AES_128_ROUNDS;
#else
    (void)k;
#endif
}

// The three entries below are QUIC's alone: two build a key from what RFC
// 9001 fixes for Initial and Retry packets, and the third is header
// protection, which a TLS record does not have. A suite build compiles
// the cipher above and none of this. aes_public_key_initial has one
// definition per build, because an AES=runtime object takes the caller's
// answer about the AES instructions (aes.h).
#ifdef CH_AES_RUNTIME
int aes_public_key_initial(aes_public_key *k, uint8_t aes_instructions, uint32_t version,
                           const uint8_t *dcid, size_t dcid_len, uint8_t endpoint) {
    uint8_t key[AES_128_KEY];
    uint8_t hp[AES_128_KEY];
    int rc = derive_initial(key, k->iv, hp, version, dcid, dcid_len, endpoint);
    if (rc != CH_OK) {
        return rc;
    }
    expand_public_key(&k->key, key, aes_instructions);
    expand_public_key(&k->hp, hp, aes_instructions);
    initial_rounds(k);
    return CH_OK;
}
#else
int aes_public_key_initial(aes_public_key *k, uint32_t version, const uint8_t *dcid,
                           size_t dcid_len, uint8_t endpoint) {
    uint8_t key[AES_128_KEY];
    uint8_t hp[AES_128_KEY];
    int rc = derive_initial(key, k->iv, hp, version, dcid, dcid_len, endpoint);
    if (rc != CH_OK) {
        return rc;
    }
    aes_expand_round_keys(key, k->key.round_keys);
    aes_expand_round_keys(hp, k->hp.round_keys);
    initial_rounds(k);
    return CH_OK;
}
#endif

void aes_public_key_retry(aes_public_key *k, uint32_t version) {
#ifdef CH_AES_RUNTIME
    // ch_srv_quic_retry_tag takes no configuration to read the caller's
    // probe result from, so both Retry calls run the printed key on the
    // table, which every CPU can run (aes.h).
    expand_public_key(&k->key, retry_key(version), CH_AES_INSTRUCTIONS_ABSENT);
#else
    aes_expand_round_keys(retry_key(version), k->key.round_keys);
#endif
#ifdef CH_AES_256
    k->key.rounds = AES_128_ROUNDS;
#endif
    // RFC 9001 §5.8 prints the nonce the caller passes to gcm_seal, and
    // a Retry packet carries no header protection, so both fields stay
    // zero rather than holding a key this call did not derive.
    memset(k->iv, 0, sizeof k->iv);
    memset(&k->hp, 0, sizeof k->hp);
}
#endif // CH_TRANSPORT_QUIC_NONBLOCKING

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
#ifdef CH_AES_TWO_CIPHERS
    // The cipher that expanded s runs it. An AES-256 schedule, above, is a
    // traffic key's, and the table holds no AES-256.
    if (!on_instructions(s)) {
        aes_soft_cipher_block(s->round_keys, in, out);
        return;
    }
#endif
    aes_cipher_block(s->round_keys, in, out);
}

void aes_encrypt_block(const aes_public_key *k, const uint8_t in[AES_BLOCK],
                       uint8_t out[AES_BLOCK]) {
    aes_encrypt_schedule(&k->key, in, out);
}

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
void aes_encrypt_block_hp(const aes_public_key *k, const uint8_t sample[AES_BLOCK],
                          uint8_t out[AES_BLOCK]) {
#ifdef CH_AES_TWO_CIPHERS
    if (!on_instructions(&k->hp)) {
        aes_soft_cipher_block(k->hp.round_keys, sample, out);
        return;
    }
#endif
    aes_cipher_block(k->hp.round_keys, sample, out);
}

#endif // CH_TRANSPORT_QUIC_NONBLOCKING

#ifdef CH_SUITE_AES_GCM
void aes_traffic_key_init(aes_traffic_key *k, const uint8_t *key, size_t key_len) {
    CH_ASSERT(key_len == AES_128_KEY || key_len == AES_256_KEY);
    // key_len is the suite's, which the ServerHello named in the clear,
    // so the branch reads a public value. The key itself goes to the AES
    // instructions or to the image's AES peripheral, never to the S-box:
    // ct.h refuses this build without AES=hw, AES=runtime or AES=extern.
    // An AES=runtime QUIC object holds the S-box too, for public keys, and
    // the line below is what keeps this key off it: every block run under
    // k takes the cipher k records (aes_schedule.h).
#ifdef CH_AES_TWO_CIPHERS
    k->key.instructions = CH_AES_INSTRUCTIONS_PRESENT;
#endif
    if (key_len == AES_256_KEY) {
        aes_expand_round_keys_256(key, k->key.round_keys);
        k->key.rounds = AES_256_ROUNDS;
        return;
    }
    aes_expand_round_keys(key, k->key.round_keys);
    k->key.rounds = AES_128_ROUNDS;
}

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
void aes_traffic_encrypt_block(const aes_traffic_key *k, const uint8_t in[AES_BLOCK],
                               uint8_t out[AES_BLOCK]) {
    aes_encrypt_schedule(&k->key, in, out);
}
#endif
#endif // CH_SUITE_AES_GCM

#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
