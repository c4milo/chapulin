// QUIC version 2 end to end, in the TRUST=raw-ecdsa build of
// test/quic_loop_test.c, over CRYPTO bytes and packets at every level. Two
// runs: a client and a server that both start in version 2, and a client
// that starts in version 1 and switches to version 2 before it reads a
// server byte, against a server started in version 2. That server stands
// in for one that chose version 2 after a version 1 hello, a choice a
// later commit adds (docs/decisions.md 79). In each run the Initial, the
// Handshake and the 1-RTT keys agree in version 2, a Handshake or 1-RTT
// packet in version 1 is refused at both ends, and a 1-RTT key update at
// each end keeps the keys agreeing, so both ends run version 2's "quicv2
// ku" label. Included by that file after quic_loop_close.h, whose
// pinned_client_config it reads.
#ifndef CH_TEST_QUIC_LOOP_VERSION_H
#define CH_TEST_QUIC_LOOP_VERSION_H

#include "quic_packet.h"

// RFC 9369 Appendix A's Destination Connection ID (rfc9369.txt:408-409).
static const uint8_t version_dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};

// One packet at level in version from one end, opened by the other: a
// long header with packet number pn in its last byte at the Initial and
// the Handshake level, a short one with Key Phase 0 at 1-RTT.
static void check_packet(ch_quic *from, ch_quic *to, uint8_t level, uint32_t version, uint8_t pn) {
    uint8_t long_hdr[6] = {0xc0, 0, 0, 0, 1, pn};
    uint8_t short_hdr[2] = {0x40, pn};
    const uint8_t *hdr = level == CH_LEVEL_APPLICATION ? short_hdr : long_hdr;
    size_t hdr_len = level == CH_LEVEL_APPLICATION ? sizeof short_hdr : sizeof long_hdr;
    static const uint8_t pt[8] = {'v', '2'};
    uint8_t pkt[64];
    size_t pkt_len = 0;
    uint8_t key_set = 0;
    uint64_t got_pn = 0;
    size_t pt_len = 0;
    CHECK(ch_quic_seal(from, level, version, pn, 1, hdr, hdr_len, pt, sizeof pt, pkt, sizeof pkt,
                       &pkt_len) == CH_OK);
    CHECK(ch_quic_open(to, level, version, pkt, pkt_len, hdr_len - 1, 0, 0, &key_set, &got_pn,
                       &pt_len) == CH_OK);
    CHECK(got_pn == pn && pt_len == sizeof pt && memcmp(pkt + hdr_len, pt, sizeof pt) == 0);
}

// The Handshake and the 1-RTT level refuse a packet in version 1 at both
// ends, the seal and the open alike (rfc9369.txt:256-259).
static void check_version_1_refused(void) {
    static const uint8_t hdr[6] = {0xc0, 0, 0, 0, 1, 3};
    static const uint8_t pt[8] = {0};
    uint8_t pkt[64];
    size_t pkt_len = 0;
    uint8_t key_set = 0;
    uint64_t pn = 0;
    size_t pt_len = 0;
    for (uint8_t level = CH_LEVEL_HANDSHAKE; level <= CH_LEVEL_APPLICATION; level++) {
        CHECK(ch_quic_seal(&server, level, CH_QUIC_VERSION_1, 3, 1, hdr, sizeof hdr, pt, sizeof pt,
                           pkt, sizeof pkt, &pkt_len) == CH_EINVAL);
        CHECK(ch_quic_seal(&client, level, CH_QUIC_VERSION_1, 3, 1, hdr, sizeof hdr, pt, sizeof pt,
                           pkt, sizeof pkt, &pkt_len) == CH_EINVAL);
        CHECK(ch_quic_seal(&server, level, CH_QUIC_VERSION_2, 3, 1, hdr, sizeof hdr, pt, sizeof pt,
                           pkt, sizeof pkt, &pkt_len) == CH_OK);
        CHECK(ch_quic_open(&client, level, CH_QUIC_VERSION_1, pkt, pkt_len, sizeof hdr - 1, 0, 0,
                           &key_set, &pn, &pt_len) == CH_EINVAL);
    }
    CHECK(client.open_failures == 0 && server.open_failures == 0);
}

// A 1-RTT key update at each end in turn (RFC 9001 section 6.2): the
// server updates and seals under its new phase, the client opens that
// packet with its next receive set and updates, and the server opens the
// client's packet under its current set, which its own update made.
static void check_key_updates(void) {
    static const uint8_t pt[16] = {'u', 'p', 'd', 'a', 't', 'e'};
    uint8_t hdr[3] = {0x41, 0x00, 0x08};
    uint8_t pkt[64];
    size_t pkt_len = 0;
    uint8_t key_set = 0;
    uint64_t pn = 0;
    size_t pt_len = 0;
    CHECK(ch_quic_key_update(&server) == CH_OK && ch_quic_key_phase(&server) == 1);
    hdr[0] |= QUIC_KEY_PHASE_BIT;
    CHECK(ch_quic_seal(&server, CH_LEVEL_APPLICATION, CH_QUIC_VERSION_2, 8, 2, hdr, sizeof hdr, pt,
                       sizeof pt, pkt, sizeof pkt, &pkt_len) == CH_OK);
    CHECK(ch_quic_open(&client, CH_LEVEL_APPLICATION, CH_QUIC_VERSION_2, pkt, pkt_len, 1, 7, 0,
                       &key_set, &pn, &pt_len) == CH_OK);
    CHECK(key_set == CH_QUIC_KEY_NEXT && pn == 8 && pt_len == sizeof pt);
    CHECK(ch_quic_key_update(&client) == CH_OK && ch_quic_key_phase(&client) == 1);
    hdr[2] = 0x09;
    CHECK(ch_quic_seal(&client, CH_LEVEL_APPLICATION, CH_QUIC_VERSION_2, 9, 2, hdr, sizeof hdr, pt,
                       sizeof pt, pkt, sizeof pkt, &pkt_len) == CH_OK);
    CHECK(ch_quic_open(&server, CH_LEVEL_APPLICATION, CH_QUIC_VERSION_2, pkt, pkt_len, 1, 8, 8,
                       &key_set, &pn, &pt_len) == CH_OK);
    CHECK(key_set == CH_QUIC_KEY_CURRENT && pn == 9 && pt_len == sizeof pt);
}

// Everything above, over one connected pair: the Initial keys of
// version_dcid in both directions, the Handshake and the 1-RTT keys, the
// version 1 refusals, and the key updates last, because they move the
// 1-RTT phase.
static void check_version_2_pair(void) {
    CHECK(ch_quic_initial_keys(&client, version_dcid, sizeof version_dcid) == CH_OK);
    CHECK(ch_quic_initial_keys(&server, version_dcid, sizeof version_dcid) == CH_OK);
    check_keys_agree_in(CH_QUIC_VERSION_2);
    for (uint8_t level = CH_LEVEL_INITIAL; level <= CH_LEVEL_APPLICATION; level++) {
        check_packet(&client, &server, level, CH_QUIC_VERSION_2, 1);
        check_packet(&server, &client, level, CH_QUIC_VERSION_2, 2);
    }
    check_version_1_refused();
    check_key_updates();
}

static void test_quic_version_2(void) {
    ch_cfg scfg;
    ch_cfg ccfg;

    // Both ends start in version 2 and never switch.
    server_config(&scfg);
    scfg.quic_original_version = CH_QUIC_VERSION_2;
    pinned_client_config(&ccfg, &server_alpn[0]);
    ccfg.quic_original_version = CH_QUIC_VERSION_2;
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(ch_quic_negotiated_version(&client) == CH_QUIC_VERSION_2);
    check_version_2_pair();

    // The client starts in version 1 and switches once, before it reads
    // the server's first byte, so every key after the Initial level is
    // version 2's, as the server's are.
    pinned_client_config(&ccfg, &server_alpn[0]);
    CHECK(run_quic_switching(&ccfg, &scfg, CH_QUIC_VERSION_2));
    CHECK(client.t.cfg.quic_original_version == CH_QUIC_VERSION_1);
    check_version_2_pair();
    CHECK(ch_quic_switch_version(&client, CH_QUIC_VERSION_1) == CH_EINVAL);
}

#endif
