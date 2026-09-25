// QUIC packet protection under the two AES-GCM suites of a
// -DCH_SUITE_AES_GCM build: the RFC 9001 §5.1 keys at the suite's hash,
// §5.3 AES-GCM packet protection, §5.4.3 AES header protection, the §6.1
// key update and §6.6's confidentiality limit. bin/quic_suite_test runs
// it on the AES instructions.
//
// No RFC prints a QUIC packet under an AES-GCM suite past the Initial
// level: RFC 9001 Appendix A protects its 1-RTT example with ChaCha20.
// The vectors below come from an independent Python computation over
// the hmac and cryptography packages, the same HKDF-Expand-Label, AES-GCM
// and AES-ECB steps the RFC names, and that computation reproduces
// Appendix A.5's "quic key", "quic hp" and "quic ku" values from its
// printed secret before it computes these. The secrets are bytes chosen
// here, 0x30 upward, one hash length long.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "quic_keys.h"
#include "quic_packet.h"

#if !defined(CH_SUITE_AES_GCM) || !defined(CH_TRANSPORT_QUIC)
#error "test/quic_suite_test.c runs the QUIC suite build: -DCH_TRANSPORT_QUIC -DCH_SUITE_AES_GCM"
#endif

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

static uint8_t nibble(char c) {
    if (c >= '0' && c <= '9') {
        return (uint8_t)(c - '0');
    }
    return (uint8_t)(c - 'a' + 10);
}

static size_t unhex(const char *hex, uint8_t *out) {
    size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; i++) {
        out[i] = (uint8_t)((nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]));
    }
    return n;
}

static int eq_hex(const uint8_t *got, size_t n, const char *hex) {
    uint8_t want[64];
    return unhex(hex, want) == n && memcmp(got, want, n) == 0;
}

typedef struct {
    uint16_t suite;
    size_t hash_len;
    size_t key_len;
    const char *key;
    const char *iv;
    const char *hp;
    const char *packet;
    const char *next_secret;
    const char *next_key;
} suite_vector;

static const suite_vector aes128 = {
    .suite = SUITE_AES_128_GCM_SHA256,
    .hash_len = 32,
    .key_len = 16,
    .key = "e7daeac0eb5e516bffb04e04d1100360",
    .iv = "92cb9e8fdee8d3cb4f50766f",
    .hp = "91fdabdf4ac6aea9a93a3ad4b12afe60",
    .packet = "5a2d1d68b163d3925ab572d88dc581c14ff84eb90024d6be9dddaa655bdfbcebc32d3ca7460c6569b2d7"
              "19",
    .next_secret = "682c16b3b6f4dec761c277362afd2a796552b3fc0ee898a96a369b1f499d9d0d",
    .next_key = "b935249675cd7f5780d47f70e7d5ad19",
};

static const suite_vector aes256 = {
    .suite = SUITE_AES_256_GCM_SHA384,
    .hash_len = 48,
    .key_len = 32,
    .key = "12387afbef811929f7c4ea8905e5dd77389dd9e722e82439d3ac8e6e54e9d14e",
    .iv = "3561c2543d441a9d19ce829f",
    .hp = "5f51f89ee1dd407f85d88ca579ac0dc0d1e465c71010a35377222b2947a8b1f2",
    .packet = "5a00b95c2dd07b0c0b0ed208dae015c7374177bf4a3dde5022392eb56ceeacc1918a17df656f85df326a"
              "df",
    .next_secret = "6e397c6afe2d45e0d61ca2e77436761b71c995e80f0c9e93db42ec1b8d2574aebd8d58f70791b880"
                   "094865c2cb99d1ef",
    .next_key = "2c4bc1a5004cd2ea1eda301611d67095c437e57e4e8846b06a93b65e7be8e680",
};

// A short header with an empty connection ID and a two-byte packet
// number, 5, and a PING padded to 24 bytes.
static const uint8_t hdr[3] = {0x41, 0x00, 0x05};
static const uint8_t pt[24] = {0x01};

static void secret_of(size_t hash_len, uint8_t *secret) {
    for (size_t i = 0; i < hash_len; i++) {
        secret[i] = (uint8_t)(0x30 + i);
    }
}

// The §5.1 derivation at the suite's hash, the seal byte for byte, the
// open of that packet back, and the §6.1 update.
static void test_suite_vector(const suite_vector *v) {
    uint8_t secret[64];
    secret_of(v->hash_len, secret);
    quic_keys k;
    quic_hp_key h;
    quic_keys_init_suite(&k, secret, v->suite);
    quic_hp_key_init_suite(&h, secret, v->suite);
    CHECK(k.suite == v->suite && h.suite == v->suite && k.sealed == 0);
    CHECK(eq_hex(k.key, v->key_len, v->key));
    CHECK(eq_hex(k.iv, AEAD_NONCE, v->iv));
    CHECK(eq_hex(h.key, v->key_len, v->hp));

    uint8_t pkt[64];
    size_t pkt_len = 0;
    CHECK(quic_packet_seal(&k, &h, CH_LEVEL_APPLICATION, 5, 2, hdr, sizeof hdr, pt, sizeof pt, pkt,
                           sizeof pkt, &pkt_len) == CH_OK);
    CHECK(eq_hex(pkt, pkt_len, v->packet));
    CHECK(k.sealed == 1);

    quic_keys sets[CH_QUIC_KEY_SETS];
    memset(sets, 0, sizeof sets);
    sets[CH_QUIC_KEY_CURRENT] = k;
    uint8_t key_set = 0;
    uint64_t pn = 0;
    size_t pt_len = 0;
    CHECK(quic_packet_open_application(sets, &h, 0, pkt, pkt_len, 1, 0, 0, &key_set, &pn,
                                       &pt_len) == CH_OK);
    CHECK(key_set == CH_QUIC_KEY_CURRENT && pn == 5 && pt_len == sizeof pt);
    CHECK(memcmp(pkt + sizeof hdr, pt, sizeof pt) == 0);

    quic_keys_update(secret, &k);
    CHECK(eq_hex(secret, v->hash_len, v->next_secret));
    CHECK(eq_hex(k.key, v->key_len, v->next_key));
    CHECK(k.suite == v->suite && k.sealed == 0);
}

// §6.6's confidentiality limit for AES-GCM: the set that has sealed one
// packet short of the refusal seals it, the next is refused and leaves
// the count alone, and a key update starts the count again. A ChaCha20
// set at the same count is not counted and seals.
static void test_confidentiality_limit(void) {
    uint8_t secret[48];
    secret_of(sizeof secret, secret);
    quic_keys k;
    quic_hp_key h;
    quic_keys_init_suite(&k, secret, SUITE_AES_256_GCM_SHA384);
    quic_hp_key_init_suite(&h, secret, SUITE_AES_256_GCM_SHA384);
    uint8_t pkt[64];
    size_t pkt_len = 0;
    k.sealed = QUIC_CONFIDENTIALITY_LIMIT - 2;
    CHECK(quic_packet_seal(&k, &h, CH_LEVEL_APPLICATION, 5, 2, hdr, sizeof hdr, pt, sizeof pt, pkt,
                           sizeof pkt, &pkt_len) == CH_OK);
    CHECK(k.sealed == QUIC_CONFIDENTIALITY_LIMIT - 1);
    CHECK(quic_packet_seal(&k, &h, CH_LEVEL_APPLICATION, 6, 2, hdr, sizeof hdr, pt, sizeof pt, pkt,
                           sizeof pkt, &pkt_len) == CH_EINVAL);
    CHECK(k.sealed == QUIC_CONFIDENTIALITY_LIMIT - 1);
    quic_keys_update(secret, &k);
    CHECK(quic_packet_seal(&k, &h, CH_LEVEL_APPLICATION, 7, 2, hdr, sizeof hdr, pt, sizeof pt, pkt,
                           sizeof pkt, &pkt_len) == CH_OK);

    uint8_t chacha_secret[32];
    secret_of(sizeof chacha_secret, chacha_secret);
    quic_keys c;
    quic_hp_key ch;
    quic_keys_init_suite(&c, chacha_secret, SUITE_CHACHA20_POLY1305_SHA256);
    quic_hp_key_init_suite(&ch, chacha_secret, SUITE_CHACHA20_POLY1305_SHA256);
    c.sealed = QUIC_CONFIDENTIALITY_LIMIT;
    CHECK(quic_packet_seal(&c, &ch, CH_LEVEL_APPLICATION, 5, 2, hdr, sizeof hdr, pt, sizeof pt, pkt,
                           sizeof pkt, &pkt_len) == CH_OK);
    CHECK(c.sealed == QUIC_CONFIDENTIALITY_LIMIT);
}

int main(void) {
    test_suite_vector(&aes128);
    test_suite_vector(&aes256);
    test_confidentiality_limit();
    if (failures == 0) {
        (void)printf("quic_suite: AES-128-GCM and AES-256-GCM packet and header protection match "
                     "an independent computation, update and count as RFC 9001 says\n");
    }
    return failures != 0;
}
