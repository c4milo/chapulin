// quic_retry.c against RFC 9001 §5.8 and Appendix A.4, in its own header
// for the reason test/gcm_tests.h is: test/quic_vectors.c holds the
// helpers these read, and it includes this header after gcm_tests.h,
// whose A4_RETRY_PACKET they read too. The last row derives each
// version's Retry key and nonce from the secret its RFC names, RFC 9369
// §3.3.3's for version 2, whose values test/quic_v2_vectors.h holds.
#ifndef CH_QUIC_RETRY_TESTS_H
#define CH_QUIC_RETRY_TESTS_H

#include "hkdf.h"
#include "quic_v2_vectors.h"

// RFC 9001 §5.8's printed key (rfc9001.txt:1499-1500), and the two
// fields aes_public_key_retry leaves zero because §5.8 prints the nonce
// and a Retry packet carries no header protection.
static void test_retry_key(void) {
    static const uint8_t retry_key[AES_128_KEY] = {0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
                                                   0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e};
    static const aes_key_schedule zero_schedule;
    static const uint8_t zero_iv[AES_IV] = {0};
    aes_public_key k;
    memset(&k, 0xa5, sizeof k);

    aes_public_key_retry(&k, CH_QUIC_VERSION_1);
    CHECK(memcmp(k.key.round_keys, retry_key, sizeof retry_key) == 0);
    CHECK(memcmp(k.iv, zero_iv, sizeof zero_iv) == 0);
    CHECK(memcmp(&k.hp, &zero_schedule, sizeof zero_schedule) == 0);
}

// RFC 9001 Appendix A.4 (rfc9001.txt:2490-2498) through the two calls
// quic_retry.h declares. test/gcm_tests.h's test_appendix_a4_retry builds the key,
// the nonce and the empty plaintext itself and drives gcm_seal and
// gcm_open; quic_retry_tag and quic_retry_ok hold all three, so this
// checks what a server sends and what a client gets rather than what a
// caller could assemble.
static void test_retry_call(void) {
    uint8_t pseudo[1 + sizeof APPENDIX_DCID + sizeof A4_RETRY_PACKET];
    size_t pseudo_len = 0;
    pseudo[pseudo_len++] = (uint8_t)sizeof APPENDIX_DCID;
    memcpy(&pseudo[pseudo_len], APPENDIX_DCID, sizeof APPENDIX_DCID);
    pseudo_len += sizeof APPENDIX_DCID;
    size_t retry_body = sizeof A4_RETRY_PACKET - GCM_TAG;
    memcpy(&pseudo[pseudo_len], A4_RETRY_PACKET, retry_body);
    pseudo_len += retry_body;
    const uint8_t *want_tag = &A4_RETRY_PACKET[retry_body];

    // The server's half of §5.8: the tag minted over that pseudo-packet,
    // against the bytes Appendix A.4 prints (rfc9001.txt:2497-2498), and
    // then through the check a client runs on it. Minting and checking
    // are one gcm_seal in quic_retry.c, and this is what holds them to
    // the RFC's answer rather than to each other.
    uint8_t minted[GCM_TAG];
    CHECK(quic_retry_tag(CH_QUIC_VERSION_1, pseudo, pseudo_len, minted) == CH_OK);
    CHECK(memcmp(minted, want_tag, sizeof minted) == 0);
    CHECK(quic_retry_ok(CH_QUIC_VERSION_1, pseudo, pseudo_len, minted) == 1);

    CHECK(quic_retry_ok(CH_QUIC_VERSION_1, pseudo, pseudo_len, want_tag) == 1);

    // The two ways a forged Retry packet differs from this one, and RFC
    // 9000 §17.2.5.2 makes the client discard both: a changed
    // pseudo-packet byte and a changed tag byte.
    pseudo[0] = (uint8_t)(pseudo[0] ^ 1);
    CHECK(quic_retry_ok(CH_QUIC_VERSION_1, pseudo, pseudo_len, want_tag) == 0);
    pseudo[0] = (uint8_t)(pseudo[0] ^ 1);

    uint8_t wrong_tag[GCM_TAG];
    memcpy(wrong_tag, want_tag, sizeof wrong_tag);
    wrong_tag[GCM_TAG - 1] = (uint8_t)(wrong_tag[GCM_TAG - 1] ^ 1);
    CHECK(quic_retry_ok(CH_QUIC_VERSION_1, pseudo, pseudo_len, wrong_tag) == 0);

    // The Original Destination Connection ID is what ties the tag to the
    // Initial packet this Retry answers, so a client that kept the wrong
    // one gets a 0 (rfc9001.txt:1531-1544).
    pseudo[1] = (uint8_t)(pseudo[1] ^ 1);
    CHECK(quic_retry_ok(CH_QUIC_VERSION_1, pseudo, pseudo_len, want_tag) == 0);
}

// The version the Retry calls take first, and the rule quic_retry.h
// states for it: a version this build derives no keys for mints no tag,
// writes no tag byte, and validates no tag, not even Appendix A.4's
// genuine one. This build derives version 1 and version 2, so 0, the
// values beside each and a version no RFC defines are each refused.
static void test_retry_versions(void) {
    uint8_t pseudo[1 + sizeof APPENDIX_DCID + sizeof A4_RETRY_PACKET];
    size_t pseudo_len = 0;
    pseudo[pseudo_len++] = (uint8_t)sizeof APPENDIX_DCID;
    memcpy(&pseudo[pseudo_len], APPENDIX_DCID, sizeof APPENDIX_DCID);
    pseudo_len += sizeof APPENDIX_DCID;
    size_t retry_body = sizeof A4_RETRY_PACKET - GCM_TAG;
    memcpy(&pseudo[pseudo_len], A4_RETRY_PACKET, retry_body);
    pseudo_len += retry_body;
    const uint8_t *want_tag = &A4_RETRY_PACKET[retry_body];

    static const uint32_t refused[] = {0, CH_QUIC_VERSION_1 + 1, CH_QUIC_VERSION_2 - 1,
                                       CH_QUIC_VERSION_2 + 1, 0x0a0a0a0aU};
    for (size_t i = 0; i < sizeof refused / sizeof refused[0]; i++) {
        uint8_t minted[GCM_TAG];
        memset(minted, 0xa5, sizeof minted);
        CHECK(quic_retry_tag(refused[i], pseudo, pseudo_len, minted) == CH_EINVAL);
        uint8_t poisoned[GCM_TAG];
        memset(poisoned, 0xa5, sizeof poisoned);
        CHECK(memcmp(minted, poisoned, sizeof minted) == 0);
        CHECK(quic_retry_ok(refused[i], pseudo, pseudo_len, want_tag) == 0);
    }
    CHECK(quic_retry_ok(CH_QUIC_VERSION_1, pseudo, pseudo_len, want_tag) == 1);
}

// One version's Retry secret, the two labels its RFC derives the key and
// the nonce under, and the key and the nonce the RFC prints.
typedef struct {
    uint32_t version;
    const char *secret;
    const char *key_label;
    const char *iv_label;
    const char *key;
    const char *nonce;
} retry_secret_row;

// Each version's printed Retry key and nonce, derived again from the
// secret its RFC names: HKDF-Expand-Label over it with the version's key
// and iv labels. The derived key must be the one aes_public_key_retry
// writes, which is aes.c's constant, and the derived nonce must give the
// tag quic_retry_tag mints under quic_retry.c's constant, so both
// constants are held to the secret as well as to the printed bytes.
static void test_retry_constants_from_secrets(void) {
    static const retry_secret_row rows[] = {
        // RFC 9001 §5.8 (rfc9001.txt:1499-1502, rfc9001.txt:1509-1512).
        {CH_QUIC_VERSION_1, "d9c9943e6101fd200021506bcc02814c73030f25c79d71ce876eca876e6fca8e",
         "quic key",                                                                                          "quic iv",   "be0c690b9f66575a1d766b54e368c84e", "461599d35d632bf2239825bb"},
        // RFC 9369 §3.3.3 (rfc9369.txt:181-188).
        {CH_QUIC_VERSION_2, V2_RETRY_SECRET,                                                    "quicv2 key", "quicv2 iv", V2_RETRY_KEY,
         V2_RETRY_NONCE                                                                                                                                                                  },
    };
    uint8_t pseudo[29];
    memset(pseudo, 0x3c, sizeof pseudo);
    for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
        uint8_t secret[SHA256_LEN];
        uint8_t key[AES_128_KEY];
        uint8_t nonce[AES_IV];
        CHECK(unhex(rows[i].secret, secret) == sizeof secret);
        hkdf_expand_label(SHA256_LEN, secret, rows[i].key_label, NULL, 0, key, sizeof key);
        hkdf_expand_label(SHA256_LEN, secret, rows[i].iv_label, NULL, 0, nonce, sizeof nonce);
        CHECK(eq_hex(key, rows[i].key) && eq_hex(nonce, rows[i].nonce));

        aes_public_key k;
        aes_public_key_retry(&k, rows[i].version);
        CHECK(memcmp(k.key.round_keys, key, sizeof key) == 0);

        // The derived key and nonce, sealed here the way quic_retry.c
        // seals, against the tag quic_retry_tag mints.
        aes_public_key derived;
        memset(&derived, 0, sizeof derived);
        aes_expand_round_keys(key, derived.key.round_keys);
#ifdef CH_AES_256
        derived.key.rounds = AES_128_ROUNDS;
#endif
        uint8_t empty[1] = {0};
        uint8_t want[GCM_TAG];
        uint8_t minted[GCM_TAG];
        gcm_seal(&derived, nonce, pseudo, sizeof pseudo, empty, 0, empty, want);
        CHECK(quic_retry_tag(rows[i].version, pseudo, sizeof pseudo, minted) == CH_OK);
        CHECK(memcmp(minted, want, sizeof want) == 0);
    }
}

#endif
