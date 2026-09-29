// Differential rows for quic_keys.c and quic_retry.c in both QUIC versions:
// the packet protection key, IV and header protection key a traffic
// secret derives (RFC 9001 §5.1), the key update (§6.1), and the Retry
// Integrity Tag (§5.8), against spec/lean/Spec/Quic.lean, which states
// each version's labels, Retry key and nonce from RFC 9001 and RFC 9369.
// test/diff_aes.h holds the Initial keys' rows, which run through aes.c.
//
// Every row names the version by its Version field in decimal, the value
// the C's CH_QUIC_VERSION_ constant holds, so a constant that drifted from
// the RFC's field would name no version the spec reads and the row would
// fail. The domain is the two versions quic_version_derived admits: the C
// refuses any other before it derives a key, and the spec answers ERR.
//
// Included by test/diff_quic_test.c only, after test/diff_aes.h.
#ifndef CH_DIFF_QUIC_H
#define CH_DIFF_QUIC_H

#include <inttypes.h>

#include "quic_keys.h"
#include "quic_retry.h"

// The two versions every row runs under.
static const uint32_t DIFF_QUIC_VERSIONS[2] = {CH_QUIC_VERSION_1, CH_QUIC_VERSION_2};

// The rows per version for the two derivations, and the longest Retry
// Pseudo-Packet: a 20-byte Original Destination Connection ID with its
// length byte, and a Retry packet with 20-byte connection IDs and a short
// token, which is RFC 9001 Appendix A.4's shape at the connection ID cap.
#define DIFF_QUIC_KEY_ROWS 40
#define DIFF_QUIC_PSEUDO_MAX 80

// quic_keys_init and quic_hp_key_init over a random SHA-256 traffic
// secret: the ChaCha20-Poly1305 key and IV, and the header protection key,
// each under the version's label.
static void diff_quic_packet_keys(void) {
    for (size_t v = 0; v < 2; v++) {
        for (int i = 0; i < DIFF_QUIC_KEY_ROWS; i++) {
            uint8_t secret[SHA256_LEN];
            rng_fill(secret, sizeof secret);
            quic_keys k;
            quic_hp_key h;
            quic_keys_init(&k, DIFF_QUIC_VERSIONS[v], secret);
            quic_hp_key_init(&h, DIFF_QUIC_VERSIONS[v], secret);

            char secret_hex[2 * SHA256_LEN + 1];
            (void)hex_encode(secret_hex, secret, sizeof secret);
            char key_hex[2 * AEAD_KEY + 1];
            (void)hex_encode(key_hex, k.key, sizeof k.key);
            char iv_hex[2 * AEAD_NONCE + 1];
            (void)hex_encode(iv_hex, k.iv, sizeof k.iv);
            char hp_hex[2 * CHACHA20_KEY + 1];
            (void)hex_encode(hp_hex, h.key, sizeof h.key);
            char want[sizeof key_hex + sizeof iv_hex + sizeof hp_hex];
            (void)snprintf(want, sizeof want, "%s %s %s", key_hex, iv_hex, hp_hex);
            char cmd[160];
            (void)snprintf(cmd, sizeof cmd, "quic_packet_keys %" PRIu32 " %s %d",
                           DIFF_QUIC_VERSIONS[v], secret_hex, AEAD_KEY);
            expect(cmd, want);
        }
    }
}

// quic_keys_update over a random secret: the next secret written back
// over its argument, and the key and IV of the set derived from it, each
// under the version's labels.
static void diff_quic_key_update(void) {
    for (size_t v = 0; v < 2; v++) {
        for (int i = 0; i < DIFF_QUIC_KEY_ROWS; i++) {
            uint8_t secret[SHA256_LEN];
            rng_fill(secret, sizeof secret);
            char secret_hex[2 * SHA256_LEN + 1];
            (void)hex_encode(secret_hex, secret, sizeof secret);
            quic_keys k;
            quic_keys_init(&k, DIFF_QUIC_VERSIONS[v], secret);
            quic_keys_update(secret, &k, DIFF_QUIC_VERSIONS[v]);

            char next_hex[2 * SHA256_LEN + 1];
            (void)hex_encode(next_hex, secret, sizeof secret);
            char key_hex[2 * AEAD_KEY + 1];
            (void)hex_encode(key_hex, k.key, sizeof k.key);
            char iv_hex[2 * AEAD_NONCE + 1];
            (void)hex_encode(iv_hex, k.iv, sizeof k.iv);
            char want[sizeof next_hex + sizeof key_hex + sizeof iv_hex];
            (void)snprintf(want, sizeof want, "%s %s %s", next_hex, key_hex, iv_hex);
            char cmd[160];
            (void)snprintf(cmd, sizeof cmd, "quic_key_update %" PRIu32 " %s", DIFF_QUIC_VERSIONS[v],
                           secret_hex);
            expect(cmd, want);
        }
    }
}

// quic_retry_tag over every pseudo-packet length up to the cap, each with
// fresh bytes. The tag is AES-128-GCM under the version's printed key and
// nonce, so these rows hold both constants to the RFCs' as the spec
// states them.
static void diff_quic_retry_tag(void) {
    for (size_t v = 0; v < 2; v++) {
        for (size_t n = 0; n <= DIFF_QUIC_PSEUDO_MAX; n++) {
            uint8_t pseudo[DIFF_QUIC_PSEUDO_MAX];
            rng_fill(pseudo, n);
            uint8_t tag[GCM_TAG];
            if (quic_retry_tag(DIFF_QUIC_VERSIONS[v], pseudo, n, tag) != CH_OK) {
                (void)fprintf(stderr, "diff: quic_retry_tag refused version %" PRIu32 "\n",
                              DIFF_QUIC_VERSIONS[v]);
                exit(1);
            }
            char pseudo_hex[2 * DIFF_QUIC_PSEUDO_MAX + 1];
            (void)hex_encode(pseudo_hex, pseudo, n);
            char want[2 * GCM_TAG + 1];
            (void)hex_encode(want, tag, sizeof tag);
            char cmd[2 * DIFF_QUIC_PSEUDO_MAX + 64];
            (void)snprintf(cmd, sizeof cmd, "quic_retry_tag %" PRIu32 " %s", DIFF_QUIC_VERSIONS[v],
                           pseudo_hex);
            expect(cmd, want);
        }
    }
}

#endif
