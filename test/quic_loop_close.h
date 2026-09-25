// The failure half of test/quic_loop_test.c, in its TRUST=raw-ecdsa build:
// a session that fails seals one CONNECTION_CLOSE at each level whose
// write keys it had, and the other end of the loop opens each one with
// the keys it holds and reads back the bytes sealed (docs/decisions.md
// 57). Included by that file, whose helpers it reads.
#ifndef CH_TEST_QUIC_LOOP_CLOSE_H
#define CH_TEST_QUIC_LOOP_CLOSE_H

// The Destination Connection ID of the client's first Initial packet,
// which both ends derive the Initial keys from (RFC 9001 section 5.2).
static const uint8_t close_dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};

static int all_zero(const void *p, size_t n) {
    const uint8_t *b = p;
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        acc |= b[i];
    }
    return acc == 0;
}

// A failed session holds no read key, no handshake state and no traffic
// secret, and its write bits are exactly write_bits.
static void check_failed(const ch_quic *q, uint8_t write_bits) {
    CHECK(ch_quic_state(q) == CH_ST_FAILED);
    CHECK(q->levels_ready == write_bits);
    CHECK(all_zero(&q->handshake_rx, sizeof q->handshake_rx));
    CHECK(all_zero(&q->handshake_hp_rx, sizeof q->handshake_hp_rx));
    CHECK(all_zero(q->app_rx, sizeof q->app_rx));
    CHECK(all_zero(&q->app_hp_rx, sizeof q->app_hp_rx));
    CHECK(all_zero(q->t.rd_secret, sizeof q->t.rd_secret));
    CHECK(all_zero(q->t.wr_secret, sizeof q->t.wr_secret));
    CHECK(all_zero(q->t.res_master, sizeof q->t.res_master));
    CHECK(all_zero(&q->hs, sizeof q->hs));
}

// The bytes quic_wipe_write_keys zeroes at one level: the stored
// connection ID at Initial, the send key set and header protection key
// at the other two.
static int write_keys_zero(const ch_quic *q, uint8_t level) {
    if (level == CH_LEVEL_INITIAL) {
        return q->initial_dcid_len == 0 && all_zero(q->initial_dcid, sizeof q->initial_dcid);
    }
    if (level == CH_LEVEL_HANDSHAKE) {
        return all_zero(&q->handshake_tx, sizeof q->handshake_tx) &&
               all_zero(&q->handshake_hp_tx, sizeof q->handshake_hp_tx);
    }
    return all_zero(&q->app_tx, sizeof q->app_tx) && all_zero(&q->app_hp_tx, sizeof q->app_hp_tx);
}

// The header each level's test packet carries, packet number 7 in its
// last byte and a one-byte packet number field: a long header at Initial
// and Handshake, a short one with Key Phase 0 at 1-RTT.
static const uint8_t close_long_hdr[6] = {0xc0, 0, 0, 0, 1, 7};
static const uint8_t close_short_hdr[2] = {0x40, 7};

static size_t close_hdr(uint8_t level, const uint8_t **hdr) {
    if (level == CH_LEVEL_APPLICATION) {
        *hdr = close_short_hdr;
        return sizeof close_short_hdr;
    }
    *hdr = close_long_hdr;
    return sizeof close_long_hdr;
}

// A packet the live peer seals at level does not open at the failed
// session, even at Initial, where the connection ID the open would derive
// from is still stored for the close.
static void check_open_refused(ch_quic *failed, ch_quic *peer, uint8_t level) {
    static const uint8_t pt[8] = {0x01};
    const uint8_t *hdr = NULL;
    size_t hdr_len = close_hdr(level, &hdr);
    uint8_t pkt[64];
    size_t pkt_len = 0;
    uint8_t key_set = 0;
    uint64_t pn = 0;
    size_t pt_len = 0;
    CHECK(ch_quic_seal(peer, level, 7, 1, hdr, hdr_len, pt, sizeof pt, pkt, sizeof pkt, &pkt_len) ==
          CH_OK);
    CHECK(ch_quic_open(failed, level, pkt, pkt_len, hdr_len - 1, 0, 0, &key_set, &pn, &pt_len) ==
          CH_EINVAL);
}

// One close from the failed session at level, opened by the peer. The
// frame is a CONNECTION_CLOSE of type 0x1c carrying ch_quic_error_code as
// a two-byte variable-length integer, CRYPTO as the frame type and no
// reason phrase. The level's write keys are zero after the one seal, and
// a second seal there is refused.
static void close_and_open(ch_quic *failed, ch_quic *peer, uint8_t level) {
    uint64_t code = ch_quic_error_code(failed);
    uint8_t frame[5] = {0x1c, (uint8_t)(0x40 | (code >> 8)), (uint8_t)code, 0x06, 0x00};
    const uint8_t *hdr = NULL;
    size_t hdr_len = close_hdr(level, &hdr);
    uint8_t pkt[64];
    size_t pkt_len = 0;
    uint8_t key_set = 0;
    uint64_t pn = 0;
    size_t pt_len = 0;
    CHECK(!write_keys_zero(failed, level));
    CHECK(ch_quic_seal_close(failed, level, 7, 1, hdr, hdr_len, frame, sizeof frame, pkt,
                             sizeof pkt, &pkt_len) == CH_OK);
    CHECK(write_keys_zero(failed, level));
    CHECK((failed->levels_ready & CH_QUIC_LEVEL_BIT(level, CH_KEY_WRITE)) == 0);
    CHECK(ch_quic_seal_close(failed, level, 7, 1, hdr, hdr_len, frame, sizeof frame, pkt,
                             sizeof pkt, &pkt_len) == CH_EINVAL);
    CHECK(ch_quic_open(peer, level, pkt, pkt_len, hdr_len - 1, 0, 0, &key_set, &pn, &pt_len) ==
          CH_OK);
    CHECK(pn == 7 && pt_len == sizeof frame && memcmp(pkt + hdr_len, frame, sizeof frame) == 0);
}

// A level whose keys were never installed owes no close.
static void check_no_close(ch_quic *failed, uint8_t level) {
    static const uint8_t frame[5] = {0x1c, 0x41, 0x0a, 0x06, 0x00};
    const uint8_t *hdr = NULL;
    size_t hdr_len = close_hdr(level, &hdr);
    uint8_t pkt[64];
    size_t pkt_len = 0;
    CHECK(ch_quic_seal_close(failed, level, 7, 1, hdr, hdr_len, frame, sizeof frame, pkt,
                             sizeof pkt, &pkt_len) == CH_EINVAL);
}

// Both ends initialized, and both holding the Initial keys of close_dcid.
static int start_close_case(const ch_cfg *ccfg, const ch_cfg *scfg) {
    memset(&from_server, 0, sizeof from_server);
    return ch_quic_init(&client, ccfg) == CH_OK && ch_srv_quic_init(&server, scfg) == CH_OK &&
           ch_quic_initial_keys(&client, close_dcid, sizeof close_dcid) == CH_OK &&
           ch_quic_initial_keys(&server, close_dcid, sizeof close_dcid) == CH_OK;
}

static void pinned_client_config(ch_cfg *ccfg, const ch_alpn_protocol *alpn) {
    client_config(ccfg, alpn);
    ccfg->server_pubkey = p256_sign_vectors[0].pub;
    ccfg->server_pubkey_len = sizeof p256_sign_vectors[0].pub;
}

// A server that fails at the ClientHello, before it has Handshake keys:
// the client offers only h2, which this server does not speak, so it
// fails with no_application_protocol (RFC 9001 section 8.1) and owes one
// close, at Initial.
static void test_server_close_at_initial(void) {
    static const uint8_t alpn_h2[2] = {'h', '2'};
    static const ch_alpn_protocol h2 = {alpn_h2, sizeof alpn_h2};
    static uint8_t buf[4096];
    ch_cfg scfg;
    ch_cfg ccfg;
    size_t n = 0;
    server_config(&scfg);
    pinned_client_config(&ccfg, &h2);
    CHECK(start_close_case(&ccfg, &scfg));
    CHECK(ch_quic_crypto_out(&client, CH_LEVEL_INITIAL, buf, sizeof buf, &n) == CH_OK);
    CHECK(ch_srv_quic_crypto_in(&server, CH_LEVEL_INITIAL, buf, n) == CH_EPROTO);
    CHECK(ch_quic_alert(&server) == ALERT_NO_APPLICATION_PROTOCOL);
    CHECK(ch_quic_error_code(&server) == 0x0100 + ALERT_NO_APPLICATION_PROTOCOL);
    CHECK(from_server.len[CH_LEVEL_INITIAL] == 0);
    check_failed(&server, CH_QUIC_LEVEL_BIT(CH_LEVEL_INITIAL, CH_KEY_WRITE));
    check_open_refused(&server, &client, CH_LEVEL_INITIAL);
    close_and_open(&server, &client, CH_LEVEL_INITIAL);
    check_no_close(&server, CH_LEVEL_HANDSHAKE);
    check_no_close(&server, CH_LEVEL_APPLICATION);
    CHECK(server.levels_ready == 0);
    ch_quic_close(&server);
    ch_quic_close(&client);
}

static const uint8_t key_update[5] = {HS_KEY_UPDATE, 0x00, 0x00, 0x01, 0x00};

// Runs a handshake until the client has staged its Finished, and takes
// the Finished into buf, which holds cap bytes. The server has not seen
// it.
static void take_client_finished(uint8_t *buf, size_t cap, size_t *n) {
    ch_cfg scfg;
    ch_cfg ccfg;
    server_config(&scfg);
    pinned_client_config(&ccfg, &server_alpn[0]);
    CHECK(start_close_case(&ccfg, &scfg));
    CHECK(ch_quic_crypto_out(&client, CH_LEVEL_INITIAL, buf, cap, n) == CH_OK);
    CHECK(ch_srv_quic_crypto_in(&server, CH_LEVEL_INITIAL, buf, *n) == CH_OK);
    CHECK(ch_quic_crypto_in(&client, CH_LEVEL_INITIAL, from_server.bytes[CH_LEVEL_INITIAL],
                            from_server.len[CH_LEVEL_INITIAL]) == CH_OK);
    CHECK(ch_quic_crypto_in(&client, CH_LEVEL_HANDSHAKE, from_server.bytes[CH_LEVEL_HANDSHAKE],
                            from_server.len[CH_LEVEL_HANDSHAKE]) == CH_OK);
    CHECK(ch_quic_crypto_out(&client, CH_LEVEL_HANDSHAKE, buf, cap, n) == CH_OK && *n > 0);
    CHECK(ch_quic_state(&client) == CH_ST_CONNECTED);
}

// A server that fails at the Handshake level, h3spec's case: the client
// sends a TLS KeyUpdate where its Finished belongs, which RFC 9001 section
// 6 makes 0x010a. The server has Initial, Handshake and 1-RTT write keys
// by then, and one close goes out at each.
static void test_server_close_at_handshake(void) {
    static uint8_t buf[4096];
    size_t n = 0;
    // The client's Finished is taken and never delivered.
    take_client_finished(buf, sizeof buf, &n);
    CHECK(ch_srv_quic_crypto_in(&server, CH_LEVEL_HANDSHAKE, key_update, sizeof key_update) ==
          CH_EPROTO);
    CHECK(ch_quic_alert(&server) == ALERT_UNEXPECTED_MESSAGE);
    CHECK(ch_quic_error_code(&server) == 0x010a);
    check_failed(&server, CH_QUIC_LEVEL_BIT(CH_LEVEL_INITIAL, CH_KEY_WRITE) |
                              CH_QUIC_LEVEL_BIT(CH_LEVEL_HANDSHAKE, CH_KEY_WRITE) |
                              CH_QUIC_LEVEL_BIT(CH_LEVEL_APPLICATION, CH_KEY_WRITE));
    for (uint8_t level = CH_LEVEL_INITIAL; level <= CH_LEVEL_APPLICATION; level++) {
        check_open_refused(&server, &client, level);
    }
    for (uint8_t level = CH_LEVEL_INITIAL; level <= CH_LEVEL_APPLICATION; level++) {
        close_and_open(&server, &client, level);
    }
    CHECK(server.levels_ready == 0 && ch_quic_state(&server) == CH_ST_FAILED);
    ch_quic_close(&server);
    ch_quic_close(&client);
}

// The client side of the same rule: a server Finished with its last byte
// flipped fails the client with decrypt_error once it holds Handshake
// keys, and the client owes one close at Initial and one at Handshake.
static void test_client_close_at_handshake(void) {
    static uint8_t buf[4096];
    ch_cfg scfg;
    ch_cfg ccfg;
    size_t n = 0;
    server_config(&scfg);
    pinned_client_config(&ccfg, &server_alpn[0]);
    CHECK(start_close_case(&ccfg, &scfg));
    CHECK(ch_quic_crypto_out(&client, CH_LEVEL_INITIAL, buf, sizeof buf, &n) == CH_OK);
    CHECK(ch_srv_quic_crypto_in(&server, CH_LEVEL_INITIAL, buf, n) == CH_OK);
    CHECK(ch_quic_crypto_in(&client, CH_LEVEL_INITIAL, from_server.bytes[CH_LEVEL_INITIAL],
                            from_server.len[CH_LEVEL_INITIAL]) == CH_OK);
    size_t flight = from_server.len[CH_LEVEL_HANDSHAKE];
    CHECK(flight > 0);
    from_server.bytes[CH_LEVEL_HANDSHAKE][flight - 1] ^= 1;
    CHECK(ch_quic_crypto_in(&client, CH_LEVEL_HANDSHAKE, from_server.bytes[CH_LEVEL_HANDSHAKE],
                            flight) != CH_OK);
    CHECK(ch_quic_alert(&client) == ALERT_DECRYPT_ERROR);
    CHECK(ch_quic_error_code(&client) == 0x0100 + ALERT_DECRYPT_ERROR);
    check_failed(&client, CH_QUIC_LEVEL_BIT(CH_LEVEL_INITIAL, CH_KEY_WRITE) |
                              CH_QUIC_LEVEL_BIT(CH_LEVEL_HANDSHAKE, CH_KEY_WRITE));
    check_open_refused(&client, &server, CH_LEVEL_INITIAL);
    check_open_refused(&client, &server, CH_LEVEL_HANDSHAKE);
    close_and_open(&client, &server, CH_LEVEL_INITIAL);
    close_and_open(&client, &server, CH_LEVEL_HANDSHAKE);
    check_no_close(&client, CH_LEVEL_APPLICATION);
    CHECK(client.levels_ready == 0);
    ch_quic_close(&client);
    ch_quic_close(&server);
}

// Delivers the client Finished with extra bytes after it in one Handshake
// call, colibri's h3spec case. The server refuses the extra bytes before
// it completes, so it never reaches CONNECTED and sends no ticket. A
// KeyUpdate takes 0x010a (RFC 9001 section 6) and any other message
// PROTOCOL_VIOLATION (section 4.1.3).
static void server_refuses_after_finished(const uint8_t *extra, size_t extra_len,
                                          uint64_t error_code) {
    static uint8_t buf[4096];
    size_t n = 0;
    take_client_finished(buf, sizeof buf, &n);
    CHECK(n + extra_len <= sizeof buf);
    memcpy(buf + n, extra, extra_len);
    CHECK(ch_srv_quic_crypto_in(&server, CH_LEVEL_HANDSHAKE, buf, n + extra_len) == CH_EPROTO);
    CHECK(ch_quic_alert(&server) == ALERT_UNEXPECTED_MESSAGE);
    CHECK(ch_quic_error_code(&server) == error_code);
    CHECK(from_server.len[CH_LEVEL_APPLICATION] == 0);
    check_failed(&server, CH_QUIC_LEVEL_BIT(CH_LEVEL_INITIAL, CH_KEY_WRITE) |
                              CH_QUIC_LEVEL_BIT(CH_LEVEL_HANDSHAKE, CH_KEY_WRITE) |
                              CH_QUIC_LEVEL_BIT(CH_LEVEL_APPLICATION, CH_KEY_WRITE));
    ch_quic_close(&server);
    ch_quic_close(&client);
}

// The client side of the same rule: the server's Handshake flight with a
// KeyUpdate after its Finished, in one call.
static void test_client_key_update_after_finished(void) {
    static uint8_t buf[4096];
    ch_cfg scfg;
    ch_cfg ccfg;
    size_t n = 0;
    server_config(&scfg);
    pinned_client_config(&ccfg, &server_alpn[0]);
    CHECK(start_close_case(&ccfg, &scfg));
    CHECK(ch_quic_crypto_out(&client, CH_LEVEL_INITIAL, buf, sizeof buf, &n) == CH_OK);
    CHECK(ch_srv_quic_crypto_in(&server, CH_LEVEL_INITIAL, buf, n) == CH_OK);
    CHECK(ch_quic_crypto_in(&client, CH_LEVEL_INITIAL, from_server.bytes[CH_LEVEL_INITIAL],
                            from_server.len[CH_LEVEL_INITIAL]) == CH_OK);
    n = from_server.len[CH_LEVEL_HANDSHAKE];
    CHECK(n + sizeof key_update <= sizeof buf);
    memcpy(buf, from_server.bytes[CH_LEVEL_HANDSHAKE], n);
    memcpy(buf + n, key_update, sizeof key_update);
    CHECK(ch_quic_crypto_in(&client, CH_LEVEL_HANDSHAKE, buf, n + sizeof key_update) == CH_EPROTO);
    CHECK(ch_quic_alert(&client) == ALERT_UNEXPECTED_MESSAGE);
    CHECK(ch_quic_error_code(&client) == 0x010a);
    CHECK(ch_quic_state(&client) == CH_ST_FAILED);
    ch_quic_close(&client);
    ch_quic_close(&server);
}

static void test_refuse_after_finished(void) {
    static const uint8_t empty_ticket[4] = {HS_NEW_SESSION_TICKET, 0x00, 0x00, 0x00};
    server_refuses_after_finished(key_update, sizeof key_update, 0x010a);
    // One byte is enough: the type names a KeyUpdate before its length does.
    server_refuses_after_finished(key_update, 1, 0x010a);
    server_refuses_after_finished(empty_ticket, sizeof empty_ticket, 0x0a);
    test_client_key_update_after_finished();
}

static void test_close_after_failure(void) {
    test_server_close_at_initial();
    test_server_close_at_handshake();
    test_client_close_at_handshake();
    test_refuse_after_finished();
}

#endif
