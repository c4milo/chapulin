// quic_retry.c against RFC 9001 §5.8 and Appendix A.4, in its own header
// for the reason test/gcm_tests.h is: test/quic_vectors.c holds the
// helpers these read, and it includes this header after gcm_tests.h,
// whose A4_RETRY_PACKET they read too.
#ifndef CH_QUIC_RETRY_TESTS_H
#define CH_QUIC_RETRY_TESTS_H

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
// genuine one. Version 1 is the one version this build derives, so 0,
// version 2 and a version no RFC defines are each refused.
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

    static const uint32_t refused[] = {0, CH_QUIC_VERSION_2, CH_QUIC_VERSION_1 + 1, 0x0a0a0a0aU};
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

#endif
