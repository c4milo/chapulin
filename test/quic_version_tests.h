// The QUIC version rules of docs/decisions.md 79 through the client's
// public calls: the original version ch_quic_init takes, the negotiated
// version it starts, the one switch ch_quic_switch_version allows, the
// version each packet call takes beside its level, and the version
// ch_quic_retry_ok checks a Retry in. test/quic_driver_test.c includes it
// after configure, build_server_hello, q and CHECK, which it reads.
//
// This build derives version 1's keys alone, so every session starts in
// version 1 and every version below is one it refuses. The switch's other
// rules, a second switch and one after a server byte, need a second
// version this build derives, and arrive with version 2's keys.
#ifndef CH_QUIC_VERSION_TESTS_H
#define CH_QUIC_VERSION_TESTS_H

#include "quic_retry.h"

// Versions this build derives no keys for: 0, the two values beside
// version 1, version 2, and a version RFC 9000 §15 reserves for
// exercising version negotiation.
static const uint32_t underived[] = {0, CH_QUIC_VERSION_1 + 1, CH_QUIC_VERSION_2, 0x0a0a0a0aU};
#define UNDERIVED_COUNT (sizeof underived / sizeof underived[0])

// ch_quic_init refuses an original version this build derives no keys
// for, 0 among them, and leaves the session failed with no negotiated
// version. Version 1 starts the session, and the negotiated version is
// the original one.
static void test_init_versions(void) {
    ch_cfg cfg;
    for (size_t i = 0; i < UNDERIVED_COUNT; i++) {
        configure(&cfg);
        cfg.quic_original_version = underived[i];
        CHECK(ch_quic_init(&q, &cfg) == CH_EINVAL && ch_quic_state(&q) == CH_ST_FAILED);
        CHECK(ch_quic_negotiated_version(&q) == 0);
    }
    configure(&cfg);
    CHECK(ch_quic_init(&q, &cfg) == CH_OK);
    CHECK(ch_quic_negotiated_version(&q) == CH_QUIC_VERSION_1);
    ch_quic_close(&q);
}

// ch_quic_switch_version refuses a switch to the negotiated version and
// to a version this build derives no keys for, changes nothing when it
// refuses, and refuses every switch once the session failed.
static void test_switch_versions(void) {
    ch_cfg cfg;
    uint8_t out[CH_TX_STAGE];
    uint8_t sh[128];
    size_t n = 0;
    configure(&cfg);
    CHECK(ch_quic_init(&q, &cfg) == CH_OK);
    CHECK(ch_quic_switch_version(&q, CH_QUIC_VERSION_1) == CH_EINVAL);
    for (size_t i = 0; i < UNDERIVED_COUNT; i++) {
        CHECK(ch_quic_switch_version(&q, underived[i]) == CH_EINVAL);
    }
    CHECK(ch_quic_negotiated_version(&q) == CH_QUIC_VERSION_1 && ch_quic_state(&q) == CH_ST_START);

    // A ServerHello naming a suite this client never offered fails the
    // session, which keeps its version and switches no more.
    CHECK(ch_quic_crypto_out(&q, CH_LEVEL_INITIAL, out, sizeof out, &n) == CH_OK);
    size_t sh_len = build_server_hello(sh, sizeof sh, 0x1301);
    CHECK(ch_quic_crypto_in(&q, CH_LEVEL_INITIAL, sh, sh_len) == CH_EPROTO);
    CHECK(ch_quic_state(&q) == CH_ST_FAILED);
    CHECK(ch_quic_switch_version(&q, CH_QUIC_VERSION_2) == CH_EINVAL);
    CHECK(ch_quic_negotiated_version(&q) == CH_QUIC_VERSION_1);
    ch_quic_close(&q);
}

// ch_quic_seal and ch_quic_open refuse a packet in a version its level
// does not admit, with CH_EINVAL and no change at all: no byte of the
// output or the packet, no count, no key. At the Initial level a packet
// in the original version opens; at the Handshake level the negotiated
// version alone does. Version 1 is both here.
static void test_packet_versions(void) {
    ch_cfg cfg;
    uint8_t out[CH_TX_STAGE];
    uint8_t sh[128];
    uint8_t dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
    uint8_t hdr[5] = {0xc0, 0, 0, 0, 1};
    uint8_t pt[8] = {0};
    uint8_t pkt[64];
    uint8_t copy[64];
    size_t n = 0;
    size_t pkt_len = 0;
    uint64_t pn = 0;
    size_t pt_len = 0;
    uint8_t key_set = 0;
    configure(&cfg);
    CHECK(ch_quic_init(&q, &cfg) == CH_OK);
    CHECK(ch_quic_crypto_out(&q, CH_LEVEL_INITIAL, out, sizeof out, &n) == CH_OK);
    CHECK(ch_quic_initial_keys(&q, dcid, sizeof dcid) == CH_OK);

    for (size_t i = 0; i < UNDERIVED_COUNT; i++) {
        memset(pkt, 0xa5, sizeof pkt);
        pkt_len = 7;
        CHECK(ch_quic_seal(&q, CH_LEVEL_INITIAL, underived[i], 1, 1, hdr, sizeof hdr, pt, sizeof pt,
                           pkt, sizeof pkt, &pkt_len) == CH_EINVAL);
        CHECK(pkt_len == 7 && pkt[0] == 0xa5 && q.initial_sealed == 0);
    }

    // The server's Initial packet in the original version.
    CHECK(quic_initial_seal(CH_QUIC_ENDPOINT_SERVER, CH_QUIC_VERSION_1, dcid, sizeof dcid, 1, 1,
                            hdr, sizeof hdr, pt, sizeof pt, pkt, sizeof pkt, &pkt_len) == CH_OK);
    memcpy(copy, pkt, pkt_len);
    for (size_t i = 0; i < UNDERIVED_COUNT; i++) {
        CHECK(ch_quic_open(&q, CH_LEVEL_INITIAL, underived[i], pkt, pkt_len, sizeof hdr - 1, 0, 0,
                           &key_set, &pn, &pt_len) == CH_EINVAL);
        CHECK(memcmp(pkt, copy, pkt_len) == 0 && q.open_failures == 0 && pn == 0);
    }
    CHECK(ch_quic_open(&q, CH_LEVEL_INITIAL, CH_QUIC_VERSION_1, pkt, pkt_len, sizeof hdr - 1, 0, 0,
                       &key_set, &pn, &pt_len) == CH_OK);
    CHECK(pn == 1 && pt_len == sizeof pt);

    // The ServerHello installs the Handshake keys. The server's send keys
    // are this client's receive keys, so a copy of them seals the
    // server's Handshake packet.
    size_t sh_len = build_server_hello(sh, sizeof sh, SUITE_CHACHA20_POLY1305_SHA256);
    CHECK(ch_quic_crypto_in(&q, CH_LEVEL_INITIAL, sh, sh_len) == CH_OK);
    quic_keys server_tx = q.handshake_rx;
    quic_hp_key server_hp = q.handshake_hp_rx;
    for (size_t i = 0; i < UNDERIVED_COUNT; i++) {
        memset(pkt, 0xa5, sizeof pkt);
        pkt_len = 7;
        CHECK(ch_quic_seal(&q, CH_LEVEL_HANDSHAKE, underived[i], 1, 1, hdr, sizeof hdr, pt,
                           sizeof pt, pkt, sizeof pkt, &pkt_len) == CH_EINVAL);
        CHECK(pkt_len == 7 && pkt[0] == 0xa5);
    }
    CHECK(ch_quic_seal(&q, CH_LEVEL_HANDSHAKE, CH_QUIC_VERSION_1, 1, 1, hdr, sizeof hdr, pt,
                       sizeof pt, pkt, sizeof pkt, &pkt_len) == CH_OK);

    CHECK(quic_packet_seal(&server_tx, &server_hp, CH_LEVEL_HANDSHAKE, 1, 1, hdr, sizeof hdr, pt,
                           sizeof pt, pkt, sizeof pkt, &pkt_len) == CH_OK);
    memcpy(copy, pkt, pkt_len);
    pn = 0;
    for (size_t i = 0; i < UNDERIVED_COUNT; i++) {
        CHECK(ch_quic_open(&q, CH_LEVEL_HANDSHAKE, underived[i], pkt, pkt_len, sizeof hdr - 1, 0, 0,
                           &key_set, &pn, &pt_len) == CH_EINVAL);
        CHECK(memcmp(pkt, copy, pkt_len) == 0 && q.open_failures == 0 && pn == 0);
    }
    CHECK(ch_quic_open(&q, CH_LEVEL_HANDSHAKE, CH_QUIC_VERSION_1, pkt, pkt_len, sizeof hdr - 1, 0,
                       0, &key_set, &pn, &pt_len) == CH_OK);
    CHECK(pn == 1 && pt_len == sizeof pt);
    ch_quic_close(&q);
}

// ch_quic_retry_ok checks a Retry in the original version alone: a tag
// minted in version 1 validates in version 1, and a Retry that names any
// other version is one a client ignores (RFC 9369 §4.1,
// rfc9369.txt:221-222).
static void test_retry_versions(void) {
    ch_cfg cfg;
    uint8_t pseudo[20];
    uint8_t tag[GCM_TAG];
    memset(pseudo, 0x3c, sizeof pseudo);
    configure(&cfg);
    CHECK(ch_quic_init(&q, &cfg) == CH_OK);
    CHECK(quic_retry_tag(CH_QUIC_VERSION_1, pseudo, sizeof pseudo, tag) == CH_OK);
    CHECK(ch_quic_retry_ok(&q, CH_QUIC_VERSION_1, pseudo, sizeof pseudo, tag) == 1);
    for (size_t i = 0; i < UNDERIVED_COUNT; i++) {
        CHECK(ch_quic_retry_ok(&q, underived[i], pseudo, sizeof pseudo, tag) == 0);
    }
    ch_quic_close(&q);
}

#endif
