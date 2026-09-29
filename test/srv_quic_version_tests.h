// The QUIC version rules of docs/decisions.md 79 through a server's
// public calls: the original version ch_srv_quic_init takes and the
// negotiated version it starts, the choice cfg.srv.choose_version makes
// at the first ClientHello, the version ch_srv_quic_retry_tag keys a
// Retry under, and, in a ROLE=both object, a switch the server session
// may not make. test/srv_quic_test.c includes it after seen, CHECK, the
// server configuration it builds and test/srv_quic_retry_tests.h's
// round, which it reads.
//
// This build derives version 1 and version 2.
#ifndef CH_SRV_QUIC_VERSION_TESTS_H
#define CH_SRV_QUIC_VERSION_TESTS_H

// Versions this build derives no keys for: 0, the values beside version 1
// and version 2, and a version RFC 9000 §15 reserves for exercising
// version negotiation.
static const uint32_t srv_underived[] = {0, CH_QUIC_VERSION_1 + 1, CH_QUIC_VERSION_2 - 1,
                                         CH_QUIC_VERSION_2 + 1, 0x0a0a0a0aU};
#define SRV_UNDERIVED_COUNT (sizeof srv_underived / sizeof srv_underived[0])

// The two versions this build derives.
static const uint32_t srv_derived[] = {CH_QUIC_VERSION_1, CH_QUIC_VERSION_2};

// ch_srv_quic_init refuses an original version this build derives no keys
// for, 0 among them, sends nothing and leaves no negotiated version.
// Version 1 and version 2 each start a session, negotiated as the
// original.
static void test_server_init_versions(const ch_cfg *base) {
    static ch_quic q;
    ch_cfg cfg = *base;
    for (size_t i = 0; i < SRV_UNDERIVED_COUNT; i++) {
        cfg.quic_original_version = srv_underived[i];
        memset(&seen, 0, sizeof seen);
        CHECK(ch_srv_quic_init(&q, &cfg) == CH_EINVAL && ch_quic_state(&q) == CH_ST_FAILED);
        CHECK(ch_quic_negotiated_version(&q) == 0 && seen.count == 0);
    }
    for (size_t i = 0; i < 2; i++) {
        cfg.quic_original_version = srv_derived[i];
        CHECK(ch_srv_quic_init(&q, &cfg) == CH_OK);
        CHECK(ch_quic_negotiated_version(&q) == srv_derived[i]);
#ifdef CH_ROLE_BOTH
        // A ROLE=both object declares ch_quic_switch_version, and RFC 9369
        // section 4.1 gives the switch to a client alone. A fresh server
        // session meets every other condition of the switch, so its role
        // is what refuses the switch to the other version.
        CHECK(ch_quic_switch_version(&q, CH_QUIC_VERSION_1) == CH_EINVAL);
        CHECK(ch_quic_switch_version(&q, CH_QUIC_VERSION_2) == CH_EINVAL);
        CHECK(ch_quic_negotiated_version(&q) == srv_derived[i]);
#endif
        ch_quic_close(&q);
    }
}

// ch_srv_quic_retry_tag refuses a version this build derives no keys for
// and writes no tag byte. In each derived version it writes the tag a
// session of that original version validates and a session of the other
// version ignores.
static void test_retry_tag_versions(const ch_cfg *base) {
    static ch_quic q;
    ch_cfg cfg = *base;
    uint8_t pseudo[20];
    uint8_t tag[GCM_TAG];
    uint8_t poisoned[GCM_TAG];
    memset(pseudo, 0x3c, sizeof pseudo);
    memset(poisoned, 0xa5, sizeof poisoned);
    for (size_t i = 0; i < SRV_UNDERIVED_COUNT; i++) {
        memset(tag, 0xa5, sizeof tag);
        CHECK(ch_srv_quic_retry_tag(srv_underived[i], pseudo, sizeof pseudo, tag) == CH_EINVAL);
        CHECK(memcmp(tag, poisoned, sizeof tag) == 0);
    }
    for (size_t i = 0; i < 2; i++) {
        uint32_t other = srv_derived[1 - i];
        CHECK(ch_srv_quic_retry_tag(srv_derived[i], pseudo, sizeof pseudo, tag) == CH_OK);
        cfg.quic_original_version = srv_derived[i];
        CHECK(ch_srv_quic_init(&q, &cfg) == CH_OK);
        CHECK(ch_quic_retry_ok(&q, srv_derived[i], pseudo, sizeof pseudo, tag) == 1);
        CHECK(ch_quic_retry_ok(&q, other, pseudo, sizeof pseudo, tag) == 0);
        ch_quic_close(&q);
        cfg.quic_original_version = other;
        CHECK(ch_srv_quic_init(&q, &cfg) == CH_OK);
        CHECK(ch_quic_retry_ok(&q, other, pseudo, sizeof pseudo, tag) == 0);
        ch_quic_close(&q);
    }
}

// What choose_answer saw: how many times it fired, the length of the
// transport parameters got_params held then, and how many CRYPTO bytes
// both sinks had taken then, which is 0 when the choice comes before the
// first byte goes out.
static struct {
    unsigned calls;
    uint32_t answer;
    size_t params_len;
    size_t sent;
} chose;

static uint32_t choose_answer(void *io) {
    (void)io;
    chose.calls++;
    chose.params_len = seen.params_len;
    chose.sent = seen.count + retry_out.len[CH_LEVEL_INITIAL] + retry_out.len[CH_LEVEL_HANDSHAKE];
    return chose.answer;
}

// One session of original version original over hello, answering answer
// when choose is set, with seen and chose reset first. Returns what
// ch_srv_quic_crypto_in returned.
static int choose_round(ch_quic *q, ch_cfg *cfg, uint32_t original, int choose, uint32_t answer,
                        const uint8_t *hello, size_t hello_len) {
    cfg->quic_original_version = original;
    cfg->srv.choose_version = choose ? choose_answer : NULL;
    memset(&seen, 0, sizeof seen);
    memset(&chose, 0, sizeof chose);
    chose.answer = answer;
    CHECK(ch_srv_quic_init(q, cfg) == CH_OK);
    return ch_srv_quic_crypto_in(q, CH_LEVEL_INITIAL, hello, hello_len);
}

// cfg.srv.choose_version at the first ClientHello: it fires once, after
// the client's transport parameters reached the caller and before any
// byte goes out, and its answer becomes the negotiated version in either
// direction and when it is the original one. NULL keeps the original
// version. An answer this build derives no keys for fails the session
// with CH_EIO and internal_error, with nothing sent and the negotiated
// version left as it was.
static void test_server_choose_version(const ch_cfg *base, const uint8_t *hello, size_t hello_len) {
    static ch_quic q;
    ch_cfg cfg = *base;
    for (size_t i = 0; i < 2; i++) {
        uint32_t original = srv_derived[i];
        CHECK(choose_round(&q, &cfg, original, 0, 0, hello, hello_len) == CH_OK);
        CHECK(ch_quic_negotiated_version(&q) == original && seen.total[CH_LEVEL_HANDSHAKE] > 0);
        ch_quic_close(&q);
        for (size_t j = 0; j < 2; j++) {
            CHECK(choose_round(&q, &cfg, original, 1, srv_derived[j], hello, hello_len) == CH_OK);
            CHECK(chose.calls == 1 && chose.params_len == sizeof client_params && chose.sent == 0);
            CHECK(ch_quic_negotiated_version(&q) == srv_derived[j]);
            CHECK(seen.total[CH_LEVEL_HANDSHAKE] > 0);
            ch_quic_close(&q);
        }
        for (size_t j = 0; j < SRV_UNDERIVED_COUNT; j++) {
            CHECK(choose_round(&q, &cfg, original, 1, srv_underived[j], hello, hello_len) ==
                  CH_EIO);
            CHECK(chose.calls == 1 && seen.count == 0 && ch_quic_state(&q) == CH_ST_FAILED);
            CHECK(ch_quic_alert(&q) == ALERT_INTERNAL_ERROR);
            CHECK(ch_quic_error_code(&q) == 0x0100U + ALERT_INTERNAL_ERROR);
            CHECK(ch_quic_negotiated_version(&q) == original);
            ch_quic_close(&q);
        }
    }
    // The choice comes before the selection, so a hello the selection then
    // refuses was still asked about: this server speaks only hq-interop,
    // and the hello offers h3 alone, which is no_application_protocol.
    cfg.alpn_protocols = retry_alpn;
    CHECK(choose_round(&q, &cfg, CH_QUIC_VERSION_1, 1, CH_QUIC_VERSION_2, hello, hello_len) ==
          CH_EPROTO);
    CHECK(chose.calls == 1 && ch_quic_alert(&q) == ALERT_NO_APPLICATION_PROTOCOL);
    CHECK(ch_quic_negotiated_version(&q) == CH_QUIC_VERSION_2 && seen.count == 0);
    ch_quic_close(&q);
}

#ifdef CH_ROLE_BOTH
// The HelloRetryRequest the server pushed, sealed in an Initial packet in
// version 2, the negotiated version, as the caller seals every CRYPTO
// frame. A client of original version 1 that switched to version 2 opens
// it. One that did not switch refuses the packet's version 2 and discards
// it when told it is version 1, because its keys are version 1's.
static void check_retry_sealed_in_version_2(ch_quic *server) {
    static const uint8_t hdr[6] = {0xc0, 0x6b, 0x33, 0x43, 0xcf, 0x00};
    static uint8_t pkt[RETRY_OUT_CAP + 64];
    static uint8_t opened[RETRY_OUT_CAP + 64];
    static uint8_t client_buf[CH_MIN_RXBUF];
    static ch_quic client;
    const uint8_t *hrr = retry_out.bytes[CH_LEVEL_INITIAL];
    size_t hrr_len = retry_out.len[CH_LEVEL_INITIAL];
    size_t pkt_len = 0;
    CHECK(ch_quic_initial_keys(server, APPENDIX_DCID, sizeof APPENDIX_DCID) == CH_OK);
    CHECK(ch_quic_seal(server, CH_LEVEL_INITIAL, CH_QUIC_VERSION_2, 0, 1, hdr, sizeof hdr, hrr,
                       hrr_len, pkt, sizeof pkt, &pkt_len) == CH_OK);
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.buf = client_buf;
    cfg.buf_len = sizeof client_buf;
    cfg.alpn_protocols = retry_alpn;
    cfg.alpn_count = 1;
    cfg.transport_params = client_params;
    cfg.transport_params_len = sizeof client_params;
    cfg.quic_original_version = CH_QUIC_VERSION_1;
    cfg.on_level_ready = level_ready;
    cfg.server_pubkey = rsa_sign_2048_n;
    cfg.server_pubkey_len = sizeof rsa_sign_2048_n;
    for (int switched = 0; switched <= 1; switched++) {
        uint8_t key_set = 0;
        uint64_t pn = 0;
        size_t pt_len = 0;
        CHECK(ch_quic_init(&client, &cfg) == CH_OK);
        CHECK(ch_quic_initial_keys(&client, APPENDIX_DCID, sizeof APPENDIX_DCID) == CH_OK);
        CHECK(!switched || ch_quic_switch_version(&client, CH_QUIC_VERSION_2) == CH_OK);
        memcpy(opened, pkt, pkt_len);
        int rc = ch_quic_open(&client, CH_LEVEL_INITIAL, CH_QUIC_VERSION_2, opened, pkt_len,
                              sizeof hdr - 1, 0, 0, &key_set, &pn, &pt_len);
        if (switched) {
            CHECK(rc == CH_OK && pt_len == hrr_len);
            CHECK(memcmp(opened + sizeof hdr, hrr, hrr_len) == 0);
        } else {
            CHECK(rc == CH_EINVAL);
            CHECK(ch_quic_open(&client, CH_LEVEL_INITIAL, CH_QUIC_VERSION_1, opened, pkt_len,
                               sizeof hdr - 1, 0, 0, &key_set, &pn, &pt_len) == CH_QUIC_DISCARD);
        }
        ch_quic_close(&client);
    }
}
#endif

// A HelloRetryRequest in version 2, over ngtcp2's recorded round: the
// server chooses version 2 at the first hello, before the retry goes out,
// so the caller seals the retry in version 2. The second hello asks
// nothing again, and the server's Handshake level then admits version 2
// alone.
static void test_retry_in_version_2(void) {
    static ch_quic q;
    static const uint8_t hdr[6] = {0xc0, 0x6b, 0x33, 0x43, 0xcf, 0x01};
    static const uint8_t pt[4] = {0x01};
    uint8_t cookie[SRV_COOKIE_MAX];
    uint8_t pkt[64];
    size_t cookie_len = 0;
    size_t pkt_len = 0;
    memset(&seen, 0, sizeof seen);
    memset(&chose, 0, sizeof chose);
    chose.answer = CH_QUIC_VERSION_2;
    retry_choose = choose_answer;
    first_round(&q, cookie, &cookie_len);
    retry_choose = NULL;
    CHECK(chose.calls == 1 && chose.sent == 0);
    CHECK(ch_quic_negotiated_version(&q) == CH_QUIC_VERSION_2);
#ifdef CH_ROLE_BOTH
    check_retry_sealed_in_version_2(&q);
#endif
    retry_msg hello2;
    recorded_second(&hello2, cookie, cookie_len, NULL);
    CHECK(ch_srv_quic_crypto_in(&q, CH_LEVEL_INITIAL, hello2.bytes, hello2.len) == CH_OK);
    CHECK(chose.calls == 1 && ch_quic_negotiated_version(&q) == CH_QUIC_VERSION_2);
    CHECK(retry_out.len[CH_LEVEL_HANDSHAKE] > 0);
    CHECK(ch_quic_seal(&q, CH_LEVEL_HANDSHAKE, CH_QUIC_VERSION_1, 1, 1, hdr, sizeof hdr, pt,
                       sizeof pt, pkt, sizeof pkt, &pkt_len) == CH_EINVAL);
    CHECK(ch_quic_seal(&q, CH_LEVEL_HANDSHAKE, CH_QUIC_VERSION_2, 1, 1, hdr, sizeof hdr, pt,
                       sizeof pt, pkt, sizeof pkt, &pkt_len) == CH_OK);
    ch_quic_close(&q);
}

#endif
