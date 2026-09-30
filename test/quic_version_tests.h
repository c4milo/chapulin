// The QUIC version rules of docs/decisions.md 79 through the client's
// public calls: the original version ch_quic_init takes, the negotiated
// version it starts, the one switch ch_quic_switch_version allows and
// each condition that refuses it, the version each packet call takes
// beside its level, and the version ch_quic_retry_ok checks a Retry in.
// test/quic_driver_test.c includes it after configure,
// build_server_hello, q and CHECK, which it reads.
//
// This build derives version 1 and version 2. A session starts in the
// version its configuration names, and the switch tests start in version
// 1 and switch to version 2, the direction the interop runner's v2 case
// takes.
#ifndef CH_QUIC_VERSION_TESTS_H
#define CH_QUIC_VERSION_TESTS_H

#include "quic_retry.h"
#include "quic_v2_vectors.h"
#include "test_widemul.h"

// Versions this build derives no keys for: 0, the values beside version 1
// and version 2, and a version RFC 9000 §15 reserves for exercising
// version negotiation.
static const uint32_t underived[] = {0, CH_QUIC_VERSION_1 + 1, CH_QUIC_VERSION_2 - 1,
                                     CH_QUIC_VERSION_2 + 1, 0x0a0a0a0aU};
#define UNDERIVED_COUNT (sizeof underived / sizeof underived[0])

// RFC 9369 Appendix A's Destination Connection ID, which RFC 9001's
// Appendix A uses too (rfc9369.txt:408-409).
static const uint8_t v2_dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};

// Hex the way test/quic_vectors.c reads it, for the RFC 9369 packet below.
static size_t version_unhex(const char *hex, uint8_t *out) {
    size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; i++) {
        const char pair[3] = {hex[2 * i], hex[2 * i + 1], 0};
        out[i] = (uint8_t)strtoul(pair, NULL, 16);
    }
    return n;
}

// ch_quic_init refuses an original version this build derives no keys
// for, 0 among them, and leaves the session failed with no negotiated
// version. Version 1 and version 2 each start a session, and the
// negotiated version is the original one.
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
    cfg.quic_original_version = CH_QUIC_VERSION_2;
    CHECK(ch_quic_init(&q, &cfg) == CH_OK);
    CHECK(ch_quic_negotiated_version(&q) == CH_QUIC_VERSION_2);
    ch_quic_close(&q);
}

// ch_quic_switch_version refuses a switch to the negotiated version and
// to a version this build derives no keys for, changes nothing when it
// refuses, and refuses every switch once the session failed, whose other
// conditions would all admit one: it waits for the ServerHello, holds no
// server byte, and has not switched.
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
    CHECK(q.step == HSQ_STEP_AWAIT_SERVER_HELLO && q.t.pt_len == 0);
    CHECK(ch_quic_switch_version(&q, CH_QUIC_VERSION_2) == CH_EINVAL);
    CHECK(ch_quic_negotiated_version(&q) == CH_QUIC_VERSION_1);
    ch_quic_close(&q);
}

// A version 1 session with its hello taken and its Initial keys
// installed, the state every switch test below starts from.
static void start_version_1(void) {
    ch_cfg cfg;
    uint8_t out[CH_TX_STAGE];
    size_t n = 0;
    configure(&cfg);
    CHECK(ch_quic_init(&q, &cfg) == CH_OK);
    CHECK(ch_quic_crypto_out(&q, CH_LEVEL_INITIAL, out, sizeof out, &n) == CH_OK && n > 0);
    CHECK(ch_quic_initial_keys(&q, v2_dcid, sizeof v2_dcid) == CH_OK);
}

// The one switch: a version 1 client switches to version 2 before any
// CRYPTO byte from the server arrived. No key moves, and the Initial keys
// of version 2 come from the same Destination Connection ID, so the server
// Initial packet RFC 9369 Appendix A.3 prints opens (rfc9369.txt:544-572).
// A second switch is refused, to either version.
static void test_switch_to_version_2(void) {
    static uint8_t pkt[256];
    uint8_t payload[128];
    uint8_t key_set = 0;
    uint64_t pn = 0;
    size_t pt_len = 0;
    start_version_1();
    CHECK(ch_quic_switch_version(&q, CH_QUIC_VERSION_2) == CH_OK);
    CHECK(ch_quic_negotiated_version(&q) == CH_QUIC_VERSION_2);
    CHECK(q.t.cfg.quic_original_version == CH_QUIC_VERSION_1 && ch_quic_state(&q) == CH_ST_START);
    CHECK(ch_quic_switch_version(&q, CH_QUIC_VERSION_1) == CH_EINVAL);
    CHECK(ch_quic_switch_version(&q, CH_QUIC_VERSION_2) == CH_EINVAL);
    CHECK(ch_quic_negotiated_version(&q) == CH_QUIC_VERSION_2);

    size_t pkt_len = version_unhex(V2_A3_PACKET, pkt);
    size_t payload_len = version_unhex(V2_A3_PAYLOAD, payload);
    CHECK(ch_quic_open(&q, CH_LEVEL_INITIAL, CH_QUIC_VERSION_2, pkt, pkt_len, 18, 0, 0, &key_set,
                       &pn, &pt_len) == CH_OK);
    CHECK(pn == 1 && pt_len == payload_len && memcmp(pkt + 20, payload, payload_len) == 0);
    ch_quic_close(&q);
}

// After a switch the Initial level admits the original version beside the
// negotiated one, because the server answers Initial packets in the
// original version until it has chosen (rfc9369.txt:246-254), and it
// derives each packet's key under the version the packet names. An
// underived version is refused at the Initial level as before.
static void test_initial_level_after_switch(void) {
    uint8_t hdr[5] = {0xc0, 0, 0, 0, 1};
    uint8_t pt[8] = {0x01};
    uint8_t pkt[64];
    size_t pkt_len = 0;
    uint8_t key_set = 0;
    uint64_t pn = 0;
    size_t pt_len = 0;
    start_version_1();
    CHECK(ch_quic_switch_version(&q, CH_QUIC_VERSION_2) == CH_OK);
    const uint32_t both[2] = {CH_QUIC_VERSION_1, CH_QUIC_VERSION_2};
    for (size_t i = 0; i < 2; i++) {
        CHECK(quic_initial_seal(CH_QUIC_ENDPOINT_SERVER, both[i], v2_dcid, sizeof v2_dcid, 1, 1,
                                hdr, sizeof hdr, pt, sizeof pt, pkt, sizeof pkt,
                                &pkt_len) == CH_OK);
        CHECK(ch_quic_open(&q, CH_LEVEL_INITIAL, both[i], pkt, pkt_len, sizeof hdr - 1, 0, 0,
                           &key_set, &pn, &pt_len) == CH_OK);
        CHECK(pn == 1 && pt_len == sizeof pt && pkt[sizeof hdr] == 0x01);
        // The client's own Initial packet in the same version, which the
        // server's entry opens. The header carries packet number 1 in its
        // last byte, and each direction has its own key.
        CHECK(ch_quic_seal(&q, CH_LEVEL_INITIAL, both[i], 1, 1, hdr, sizeof hdr, pt, sizeof pt, pkt,
                           sizeof pkt, &pkt_len) == CH_OK);
        CHECK(quic_initial_open(CH_QUIC_ENDPOINT_SERVER, both[i], v2_dcid, sizeof v2_dcid, pkt,
                                pkt_len, sizeof hdr - 1, 0, &pn, &pt_len) == CH_OK);
        CHECK(pn == 1 && pt_len == sizeof pt && pkt[sizeof hdr] == 0x01);
    }
    for (size_t i = 0; i < UNDERIVED_COUNT; i++) {
        CHECK(ch_quic_seal(&q, CH_LEVEL_INITIAL, underived[i], 3, 1, hdr, sizeof hdr, pt, sizeof pt,
                           pkt, sizeof pkt, &pkt_len) == CH_EINVAL);
    }
    CHECK(q.initial_sealed == 2 && q.open_failures == 0);
    ch_quic_close(&q);
}

// After a switch the ServerHello installs the Handshake keys under
// version 2's labels: each is the set quic_keys_init derives from its
// handshake traffic secret in version 2, and not the one it derives in
// version 1. The Handshake level admits the negotiated version alone, so
// a Handshake packet in the original version is refused both ways, with
// nothing written and nothing counted (rfc9369.txt:256-259).
static void test_handshake_level_after_switch(void) {
    uint8_t sh[128];
    uint8_t hdr[5] = {0xc0, 0, 0, 0, 1};
    uint8_t pt[8] = {0x02};
    uint8_t pkt[64];
    uint8_t copy[64];
    size_t pkt_len = 0;
    uint8_t key_set = 0;
    uint64_t pn = 0;
    size_t pt_len = 0;
    start_version_1();
    CHECK(ch_quic_switch_version(&q, CH_QUIC_VERSION_2) == CH_OK);
    size_t sh_len = build_server_hello(sh, sizeof sh, SUITE_CHACHA20_POLY1305_SHA256);
    CHECK(ch_quic_crypto_in(&q, CH_LEVEL_INITIAL, sh, sh_len) == CH_OK);

    quic_keys v2_rx;
    quic_keys v1_rx;
    quic_keys v2_tx;
    quic_hp_key v2_hp_rx;
    quic_hp_key v2_hp_tx;
    quic_keys_init(&v2_rx, CH_QUIC_VERSION_2, q.hs.s_hs);
    quic_keys_init(&v1_rx, CH_QUIC_VERSION_1, q.hs.s_hs);
    quic_keys_init(&v2_tx, CH_QUIC_VERSION_2, q.hs.c_hs);
    quic_hp_key_init(&v2_hp_rx, CH_QUIC_VERSION_2, q.hs.s_hs);
    quic_hp_key_init(&v2_hp_tx, CH_QUIC_VERSION_2, q.hs.c_hs);
    CHECK(memcmp(&q.handshake_rx, &v2_rx, sizeof v2_rx) == 0);
    CHECK(memcmp(&q.handshake_rx, &v1_rx, sizeof v1_rx) != 0);
    CHECK(memcmp(&q.handshake_tx, &v2_tx, sizeof v2_tx) == 0);
    CHECK(memcmp(&q.handshake_hp_rx, &v2_hp_rx, sizeof v2_hp_rx) == 0);
    CHECK(memcmp(&q.handshake_hp_tx, &v2_hp_tx, sizeof v2_hp_tx) == 0);

    memset(pkt, 0xa5, sizeof pkt);
    pkt_len = 7;
    CHECK(ch_quic_seal(&q, CH_LEVEL_HANDSHAKE, CH_QUIC_VERSION_1, 1, 1, hdr, sizeof hdr, pt,
                       sizeof pt, pkt, sizeof pkt, &pkt_len) == CH_EINVAL);
    CHECK(pkt_len == 7 && pkt[0] == 0xa5);
    CHECK(ch_quic_seal(&q, CH_LEVEL_HANDSHAKE, CH_QUIC_VERSION_2, 1, 1, hdr, sizeof hdr, pt,
                       sizeof pt, pkt, sizeof pkt, &pkt_len) == CH_OK);

    // The server's Handshake packet, sealed under this client's receive
    // keys, which are the server's send keys.
    CHECK(quic_packet_seal(TEST_WIDEMUL, &v2_rx, &v2_hp_rx, CH_LEVEL_HANDSHAKE, 1, 1, hdr,
                           sizeof hdr, pt, sizeof pt, pkt, sizeof pkt, &pkt_len) == CH_OK);
    memcpy(copy, pkt, pkt_len);
    CHECK(ch_quic_open(&q, CH_LEVEL_HANDSHAKE, CH_QUIC_VERSION_1, pkt, pkt_len, sizeof hdr - 1, 0,
                       0, &key_set, &pn, &pt_len) == CH_EINVAL);
    CHECK(memcmp(pkt, copy, pkt_len) == 0 && q.open_failures == 0 && pn == 0);
    CHECK(ch_quic_open(&q, CH_LEVEL_HANDSHAKE, CH_QUIC_VERSION_2, pkt, pkt_len, sizeof hdr - 1, 0,
                       0, &key_set, &pn, &pt_len) == CH_OK);
    CHECK(pn == 1 && pt_len == sizeof pt && pkt[sizeof hdr] == 0x02);
    // The switch was the one switch, and the ServerHello ended its window.
    CHECK(ch_quic_switch_version(&q, CH_QUIC_VERSION_1) == CH_EINVAL);
    ch_quic_close(&q);
}

// The switch's two server-byte conditions, each on its own. One byte of
// the ServerHello delivered is a server byte, so the switch is refused
// while the session still waits for the rest. After the ServerHello step,
// a delivery of no bytes at the Handshake level empties cfg.buf, so the
// buffer no longer shows that a byte arrived and the step alone refuses.
// Either way the session keeps version 1 and its Handshake keys take
// version 1's labels.
static void test_switch_after_server_bytes(void) {
    uint8_t sh[128];
    size_t sh_len = build_server_hello(sh, sizeof sh, SUITE_CHACHA20_POLY1305_SHA256);
    start_version_1();
    CHECK(ch_quic_crypto_in(&q, CH_LEVEL_INITIAL, sh, 1) == CH_OK);
    CHECK(q.t.pt_len == 1 && q.step == HSQ_STEP_AWAIT_SERVER_HELLO);
    CHECK(ch_quic_switch_version(&q, CH_QUIC_VERSION_2) == CH_EINVAL);
    CHECK(ch_quic_negotiated_version(&q) == CH_QUIC_VERSION_1);
    CHECK(ch_quic_crypto_in(&q, CH_LEVEL_INITIAL, sh + 1, sh_len - 1) == CH_OK);
    quic_keys v1_rx;
    quic_keys_init(&v1_rx, CH_QUIC_VERSION_1, q.hs.s_hs);
    CHECK(memcmp(&q.handshake_rx, &v1_rx, sizeof v1_rx) == 0);
    ch_quic_close(&q);

    start_version_1();
    CHECK(ch_quic_crypto_in(&q, CH_LEVEL_INITIAL, sh, sh_len) == CH_OK);
    CHECK(ch_quic_crypto_in(&q, CH_LEVEL_HANDSHAKE, sh, 0) == CH_OK);
    CHECK(q.t.pt_len == 0 && q.step == HSQ_STEP_AWAIT_ENCRYPTED_EXTENSIONS);
    CHECK(ch_quic_switch_version(&q, CH_QUIC_VERSION_2) == CH_EINVAL);
    CHECK(ch_quic_negotiated_version(&q) == CH_QUIC_VERSION_1 && ch_quic_state(&q) == CH_ST_START);
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

    // underived's versions and version 2, which this build derives and
    // this session never switched to, so neither level admits it.
    static const uint32_t refused[] = {
        0,           CH_QUIC_VERSION_1 + 1, CH_QUIC_VERSION_2 - 1, CH_QUIC_VERSION_2 + 1,
        0x0a0a0a0aU, CH_QUIC_VERSION_2};
    const size_t refused_count = sizeof refused / sizeof refused[0];
    for (size_t i = 0; i < refused_count; i++) {
        memset(pkt, 0xa5, sizeof pkt);
        pkt_len = 7;
        CHECK(ch_quic_seal(&q, CH_LEVEL_INITIAL, refused[i], 1, 1, hdr, sizeof hdr, pt, sizeof pt,
                           pkt, sizeof pkt, &pkt_len) == CH_EINVAL);
        CHECK(pkt_len == 7 && pkt[0] == 0xa5 && q.initial_sealed == 0);
    }

    // The server's Initial packet in the original version.
    CHECK(quic_initial_seal(CH_QUIC_ENDPOINT_SERVER, CH_QUIC_VERSION_1, dcid, sizeof dcid, 1, 1,
                            hdr, sizeof hdr, pt, sizeof pt, pkt, sizeof pkt, &pkt_len) == CH_OK);
    memcpy(copy, pkt, pkt_len);
    for (size_t i = 0; i < refused_count; i++) {
        CHECK(ch_quic_open(&q, CH_LEVEL_INITIAL, refused[i], pkt, pkt_len, sizeof hdr - 1, 0, 0,
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
    for (size_t i = 0; i < refused_count; i++) {
        memset(pkt, 0xa5, sizeof pkt);
        pkt_len = 7;
        CHECK(ch_quic_seal(&q, CH_LEVEL_HANDSHAKE, refused[i], 1, 1, hdr, sizeof hdr, pt, sizeof pt,
                           pkt, sizeof pkt, &pkt_len) == CH_EINVAL);
        CHECK(pkt_len == 7 && pkt[0] == 0xa5);
    }
    CHECK(ch_quic_seal(&q, CH_LEVEL_HANDSHAKE, CH_QUIC_VERSION_1, 1, 1, hdr, sizeof hdr, pt,
                       sizeof pt, pkt, sizeof pkt, &pkt_len) == CH_OK);

    CHECK(quic_packet_seal(TEST_WIDEMUL, &server_tx, &server_hp, CH_LEVEL_HANDSHAKE, 1, 1, hdr,
                           sizeof hdr, pt, sizeof pt, pkt, sizeof pkt, &pkt_len) == CH_OK);
    memcpy(copy, pkt, pkt_len);
    pn = 0;
    for (size_t i = 0; i < refused_count; i++) {
        CHECK(ch_quic_open(&q, CH_LEVEL_HANDSHAKE, refused[i], pkt, pkt_len, sizeof hdr - 1, 0, 0,
                           &key_set, &pn, &pt_len) == CH_EINVAL);
        CHECK(memcmp(pkt, copy, pkt_len) == 0 && q.open_failures == 0 && pn == 0);
    }
    CHECK(ch_quic_open(&q, CH_LEVEL_HANDSHAKE, CH_QUIC_VERSION_1, pkt, pkt_len, sizeof hdr - 1, 0,
                       0, &key_set, &pn, &pt_len) == CH_OK);
    CHECK(pn == 1 && pt_len == sizeof pt);
    ch_quic_close(&q);
}

// ch_quic_retry_ok checks a Retry in the original version alone: a tag
// minted in the original version validates, and a Retry that names any
// other version is one a client ignores (RFC 9369 §4.1,
// rfc9369.txt:221-222), version 2 among them for a version 1 session and
// version 1 for a version 2 session, whose tag is minted in version 2.
static void test_retry_versions(void) {
    ch_cfg cfg;
    uint8_t pseudo[20];
    uint8_t tag[GCM_TAG];
    memset(pseudo, 0x3c, sizeof pseudo);
    configure(&cfg);
    CHECK(ch_quic_init(&q, &cfg) == CH_OK);
    CHECK(quic_retry_tag(CH_QUIC_VERSION_1, pseudo, sizeof pseudo, tag) == CH_OK);
    CHECK(ch_quic_retry_ok(&q, CH_QUIC_VERSION_1, pseudo, sizeof pseudo, tag) == 1);
    CHECK(ch_quic_retry_ok(&q, CH_QUIC_VERSION_2, pseudo, sizeof pseudo, tag) == 0);
    for (size_t i = 0; i < UNDERIVED_COUNT; i++) {
        CHECK(ch_quic_retry_ok(&q, underived[i], pseudo, sizeof pseudo, tag) == 0);
    }
    ch_quic_close(&q);

    cfg.quic_original_version = CH_QUIC_VERSION_2;
    CHECK(ch_quic_init(&q, &cfg) == CH_OK);
    CHECK(quic_retry_tag(CH_QUIC_VERSION_2, pseudo, sizeof pseudo, tag) == CH_OK);
    CHECK(ch_quic_retry_ok(&q, CH_QUIC_VERSION_2, pseudo, sizeof pseudo, tag) == 1);
    CHECK(ch_quic_retry_ok(&q, CH_QUIC_VERSION_1, pseudo, sizeof pseudo, tag) == 0);
    ch_quic_close(&q);
}

static void test_versions(void) {
    test_init_versions();
    test_switch_versions();
    test_switch_to_version_2();
    test_initial_level_after_switch();
    test_handshake_level_after_switch();
    test_switch_after_server_bytes();
    test_packet_versions();
    test_retry_versions();
}

#endif
