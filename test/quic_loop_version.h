// QUIC version 2 end to end, in the TRUST=raw-ecdsa build of
// test/quic_loop_test.c, over CRYPTO bytes and packets at every level.
// Three runs negotiate version 2: a client and a server that both start in
// it; a version 1 client against a server whose choose_version answers
// version 2, where the test acts as colibri at both ends, packet by packet,
// and switches the client when the server's first Initial packet carries
// version 2 (rfc9369.txt:240-244); and the same after a version 1 Retry
// with its token (rfc9369.txt:221-227). In each run the Initial, the Handshake
// and the 1-RTT keys agree in version 2, a Handshake or 1-RTT packet in
// version 1 is refused at both ends, and a 1-RTT key update at each end
// keeps the keys agreeing, so both ends run version 2's "quicv2 ku" label.
// A client that does not switch opens none of that server's packets.
// Included by that file after quic_loop_close.h, whose
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

// One packet of the negotiation, as colibri moves it: the sender's CRYPTO
// bytes at the Initial or the Handshake level behind a long header whose
// Version field is the sender's negotiated version, and the packet number
// pn in its one-byte packet number field.
static uint8_t negotiation_packet[sizeof from_server.bytes[0] + 64];
static size_t negotiation_packet_len;

static int send_crypto(ch_quic *from, uint8_t level, uint8_t pn, const uint8_t *bytes, size_t n) {
    uint32_t version = ch_quic_negotiated_version(from);
    uint8_t hdr[6] = {0xc0,
                      (uint8_t)(version >> 24),
                      (uint8_t)(version >> 16),
                      (uint8_t)(version >> 8),
                      (uint8_t)version,
                      pn};
    return ch_quic_seal(from, level, version, pn, 1, hdr, sizeof hdr, bytes, n, negotiation_packet,
                        sizeof negotiation_packet, &negotiation_packet_len) == CH_OK;
}

// The Version field of the packet in negotiation_packet, which header
// protection leaves in the clear (RFC 9001 section 5.4.1), so colibri
// reads it before it opens the packet.
static uint32_t wire_version(void) {
    return (uint32_t)negotiation_packet[1] << 24 | (uint32_t)negotiation_packet[2] << 16 |
           (uint32_t)negotiation_packet[3] << 8 | negotiation_packet[4];
}

// Opens the packet in negotiation_packet at level as a packet of version,
// which colibri reads off the header, and writes where the CRYPTO bytes
// sit. Returns what ch_quic_open returned.
static int open_crypto(ch_quic *to, uint8_t level, uint32_t version, const uint8_t **bytes,
                       size_t *n) {
    uint8_t key_set = 0;
    uint64_t pn = 0;
    int rc = ch_quic_open(to, level, version, negotiation_packet, negotiation_packet_len, 5, 0, 0,
                          &key_set, &pn, n);
    *bytes = negotiation_packet + 6;
    return rc;
}

// A version 1 client against a server whose choose_version answers
// version 2, packet by packet from the client's Initial packet that
// carries hello, with the test acting as colibri at both ends. Both
// sessions hold their Initial keys already. The server opens that packet
// in version 1, its original version, and seals every packet after the
// choice in version 2. The test reads the Version field of the server's
// first Initial packet, and because it differs from the client's original
// version it switches the client before it opens that packet. Returns 1
// when both ends are connected, and 0 at the first refusal.
static int negotiate(const uint8_t *hello, size_t hello_len) {
    static uint8_t buf[4096];
    const uint8_t *pt = NULL;
    size_t pt_len = 0;
    size_t n = 0;
    memset(&from_server, 0, sizeof from_server);
    if (!send_crypto(&client, CH_LEVEL_INITIAL, 0, hello, hello_len) ||
        wire_version() != CH_QUIC_VERSION_1 ||
        open_crypto(&server, CH_LEVEL_INITIAL, wire_version(), &pt, &pt_len) != CH_OK ||
        ch_srv_quic_crypto_in(&server, CH_LEVEL_INITIAL, pt, pt_len) != CH_OK) {
        return 0;
    }
    if (!send_crypto(&server, CH_LEVEL_INITIAL, 0, from_server.bytes[CH_LEVEL_INITIAL],
                     from_server.len[CH_LEVEL_INITIAL]) ||
        wire_version() == ch_quic_negotiated_version(&client) ||
        ch_quic_switch_version(&client, wire_version()) != CH_OK ||
        open_crypto(&client, CH_LEVEL_INITIAL, wire_version(), &pt, &pt_len) != CH_OK ||
        ch_quic_crypto_in(&client, CH_LEVEL_INITIAL, pt, pt_len) != CH_OK) {
        return 0;
    }
    if (!send_crypto(&server, CH_LEVEL_HANDSHAKE, 0, from_server.bytes[CH_LEVEL_HANDSHAKE],
                     from_server.len[CH_LEVEL_HANDSHAKE]) ||
        open_crypto(&client, CH_LEVEL_HANDSHAKE, wire_version(), &pt, &pt_len) != CH_OK ||
        ch_quic_crypto_in(&client, CH_LEVEL_HANDSHAKE, pt, pt_len) != CH_OK ||
        ch_quic_crypto_out(&client, CH_LEVEL_HANDSHAKE, buf, sizeof buf, &n) != CH_OK ||
        !send_crypto(&client, CH_LEVEL_HANDSHAKE, 0, buf, n) ||
        open_crypto(&server, CH_LEVEL_HANDSHAKE, wire_version(), &pt, &pt_len) != CH_OK ||
        ch_srv_quic_crypto_in(&server, CH_LEVEL_HANDSHAKE, pt, pt_len) != CH_OK) {
        return 0;
    }
    return ch_quic_state(&client) == CH_ST_CONNECTED && ch_quic_state(&server) == CH_ST_CONNECTED;
}

// The negotiation from init on, both ends holding the Initial keys of
// version_dcid.
static int run_negotiated(const ch_cfg *ccfg, const ch_cfg *scfg) {
    static uint8_t hello[4096];
    size_t n = 0;
    return start_close_case(ccfg, scfg) &&
           ch_quic_crypto_out(&client, CH_LEVEL_INITIAL, hello, sizeof hello, &n) == CH_OK &&
           negotiate(hello, n);
}

// A client that never switches, against the same server, with the CRYPTO
// bytes handed over directly: both TLS handshakes complete, but the client
// derived its keys under version 1 and the server under version 2. The
// server's Initial and Handshake packets in version 2 are then a version
// the client does not admit, and opened as version 1 packets, which the
// client admits, they fail to authenticate and are discarded.
static void check_unswitched_client(const ch_cfg *ccfg, const ch_cfg *scfg) {
    const uint8_t *pt = NULL;
    size_t pt_len = 0;
    CHECK(run_quic_following(ccfg, scfg, 0));
    CHECK(ch_quic_negotiated_version(&client) == CH_QUIC_VERSION_1);
    CHECK(ch_quic_negotiated_version(&server) == CH_QUIC_VERSION_2);
    CHECK(ch_quic_initial_keys(&client, version_dcid, sizeof version_dcid) == CH_OK);
    CHECK(ch_quic_initial_keys(&server, version_dcid, sizeof version_dcid) == CH_OK);
    for (uint8_t level = CH_LEVEL_INITIAL; level <= CH_LEVEL_HANDSHAKE; level++) {
        CHECK(send_crypto(&server, level, 4, from_server.bytes[level], from_server.len[level]));
        CHECK(wire_version() == CH_QUIC_VERSION_2);
        CHECK(open_crypto(&client, level, CH_QUIC_VERSION_2, &pt, &pt_len) == CH_EINVAL);
        CHECK(open_crypto(&client, level, CH_QUIC_VERSION_1, &pt, &pt_len) == CH_QUIC_DISCARD);
    }
}

// The Retry pseudo-packet of RFC 9001 section 5.8 for a version 1 Retry
// that carries token and names retry_scid, after the Original Destination
// Connection ID version_dcid (rfc9001.txt:1514-1529): the ID's length and
// bytes, the first byte with the version 1 Retry type, the Version field,
// an empty Destination Connection ID, the Source Connection ID and the
// token. chapulin reads none of it; the integrity tag covers all of it.
static size_t retry_pseudo(uint8_t *out, const uint8_t *retry_scid, size_t scid_len,
                           const uint8_t *token, size_t token_len) {
    size_t n = 0;
    out[n++] = sizeof version_dcid;
    memcpy(out + n, version_dcid, sizeof version_dcid);
    n += sizeof version_dcid;
    static const uint8_t head[6] = {0xf0, 0x00, 0x00, 0x00, 0x01, 0x00};
    memcpy(out + n, head, sizeof head);
    n += sizeof head;
    out[n++] = (uint8_t)scid_len;
    memcpy(out + n, retry_scid, scid_len);
    n += scid_len;
    memcpy(out + n, token, token_len);
    return n + token_len;
}

// A Retry in version 1, then the switch to version 2 (rfc9369.txt:221-227).
// The server sends the Retry before it has a session: a token bound to
// version 1 and to the client's address, and the integrity tag under
// version 1's key, which the client takes and a version 2 check refuses.
// Both ends derive their Initial keys from the Retry's Source Connection
// ID, and the client sends its hello again in version 1 with the token.
// The server checks the token under version 1, the Version field of that
// packet, where version 2 would refuse it, starts its session in version
// 1, and the negotiation then runs as above and ends in version 2.
static void test_retry_then_switch(void) {
    static const uint8_t token_key[CH_QUIC_TOKEN_KEY_LEN] = {0x42, 0x24};
    static const uint8_t address[6] = {192, 0, 2, 1, 0x11, 0x51};
    static const uint8_t retry_scid[8] = {0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5};
    static uint8_t hello[4096];
    uint8_t token[CH_QUIC_TOKEN_MAX];
    uint8_t pseudo[1 + CH_QUIC_DCID_MAX + 6 + 1 + CH_QUIC_DCID_MAX + CH_QUIC_TOKEN_MAX];
    uint8_t tag[GCM_TAG];
    size_t hello_len = 0;
    size_t token_len = 0;
    ch_cfg scfg;
    ch_cfg ccfg;
    server_config(&scfg);
    scfg.srv.choose_version = choose_version_2;
    pinned_client_config(&ccfg, &server_alpn[0]);
    CHECK(ch_quic_init(&client, &ccfg) == CH_OK);
    CHECK(ch_quic_crypto_out(&client, CH_LEVEL_INITIAL, hello, sizeof hello, &hello_len) == CH_OK);

    ch_quic_retry_cids cids;
    memset(&cids, 0, sizeof cids);
    memcpy(cids.original_dcid, version_dcid, sizeof version_dcid);
    cids.original_dcid_len = sizeof version_dcid;
    memcpy(cids.retry_scid, retry_scid, sizeof retry_scid);
    cids.retry_scid_len = sizeof retry_scid;
    CHECK(ch_srv_quic_token_mint(token_key, CH_QUIC_VERSION_1, address, sizeof address, &cids,
                                 LOOP_NOW, token, sizeof token, &token_len) == CH_OK);
    size_t pseudo_len = retry_pseudo(pseudo, retry_scid, sizeof retry_scid, token, token_len);
    CHECK(ch_srv_quic_retry_tag(CH_QUIC_VERSION_1, pseudo, pseudo_len, tag) == CH_OK);
    CHECK(ch_quic_retry_ok(&client, CH_QUIC_VERSION_1, pseudo, pseudo_len, tag) == 1);
    CHECK(ch_quic_retry_ok(&client, CH_QUIC_VERSION_2, pseudo, pseudo_len, tag) == 0);

    ch_quic_retry_cids got;
    CHECK(ch_srv_quic_token_check(token_key, CH_QUIC_VERSION_2, token, token_len, address,
                                  sizeof address, LOOP_NOW + 1, 10, &got) == CH_EAUTH);
    CHECK(ch_srv_quic_token_check(token_key, CH_QUIC_VERSION_1, token, token_len, address,
                                  sizeof address, LOOP_NOW + 1, 10, &got) == CH_OK);
    CHECK(got.original_dcid_len == sizeof version_dcid &&
          memcmp(got.original_dcid, version_dcid, sizeof version_dcid) == 0);
    choose_calls = 0;
    CHECK(ch_srv_quic_init(&server, &scfg) == CH_OK);
    CHECK(ch_quic_initial_keys(&client, retry_scid, sizeof retry_scid) == CH_OK);
    CHECK(ch_quic_initial_keys(&server, retry_scid, sizeof retry_scid) == CH_OK);
    CHECK(negotiate(hello, hello_len));
    CHECK(choose_calls == 1);
    CHECK(ch_quic_negotiated_version(&client) == CH_QUIC_VERSION_2);
    check_version_2_pair();
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

    // Compatible negotiation: both ends start in version 1, the server
    // chooses version 2 once, and the client switches on the Version field
    // of the server's first Initial packet.
    server_config(&scfg);
    scfg.srv.choose_version = choose_version_2;
    pinned_client_config(&ccfg, &server_alpn[0]);
    choose_calls = 0;
    CHECK(run_negotiated(&ccfg, &scfg));
    CHECK(choose_calls == 1);
    CHECK(client.t.cfg.quic_original_version == CH_QUIC_VERSION_1);
    CHECK(server.t.cfg.quic_original_version == CH_QUIC_VERSION_1);
    check_version_2_pair();
    CHECK(ch_quic_switch_version(&client, CH_QUIC_VERSION_1) == CH_EINVAL);

    check_unswitched_client(&ccfg, &scfg);
    test_retry_then_switch();
}

#endif
