// The TRUST=webpki half of test/quic_loop_test.c. Included by that file,
// whose helpers it reads.
//
// The server presents the r2 corpus chain and signs with its leaf key
// (test/webpki_r2_chain.h), so the client runs the whole handshake: the
// chain walk against the r2 anchor, the hostname and the clock. The
// ticket that handshake ends with resumes the next connection with no
// Certificate. A server that holds another ticket key cannot open it,
// declines it, and the same connection completes as a full handshake
// with the chain checked as before (docs/decisions.md 55).
//
// It also holds CH_HELLO_MAX to the largest hello a QUIC webpki client
// builds, which carries the server_certificate_type offer since
// ch_quic_init takes SPKI pins (docs/decisions.md 64).
#ifndef CH_TEST_QUIC_LOOP_WEBPKI_H
#define CH_TEST_QUIC_LOOP_WEBPKI_H

#include "webpki_r2_chain.h"

static const uint8_t other_ticket_key[SRV_TICKET_KEY_LEN] = {
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30};

// This tree's server with the r2 identity, sealing and opening tickets
// under key.
static void webpki_server(ch_cfg *cfg, const uint8_t *key) {
    server_config(cfg);
    CHECK(r2_identity(&cfg->srv.ecdsa_p256));
    cfg->srv.ticket_key = key;
}

// The client that verifies the r2 chain under root for hostname.
static void webpki_client(ch_cfg *cfg, const webpki_corpus_anchor *root, const char *hostname) {
    client_config(cfg, &server_alpn[0]);
    r2_trust(cfg, root, hostname);
}

// Whether the kept ticket's binding is the one webpki_ticket.h gives its
// PSK under cfg's hostname and anchors, which is only true if
// ch_quic_init took the configuration hash.
static int kept_ticket_bound(const ch_cfg *cfg) {
    uint8_t config_hash[SHA256_LEN];
    uint8_t want[SHA256_LEN];
    webpki_ticket_config_hash(cfg, config_hash);
    webpki_ticket_binding(kept.psk, kept.psk_len, config_hash, want);
    return memcmp(kept.binding, want, sizeof want) == 0;
}

// A server that declines the ticket, and a client whose trust the r2
// chain fails: the handshake dies at the Certificate with the walk's
// alert, which RFC 9001 §4.8 carries as 0x0100 plus the alert.
static void check_declined_chain_refused(const webpki_corpus_anchor *root, const char *hostname,
                                         uint8_t alert) {
    ch_cfg scfg;
    ch_cfg ccfg;
    uint8_t binding[SHA256_LEN];
    memcpy(binding, kept.binding, sizeof binding);
    webpki_server(&scfg, other_ticket_key);
    webpki_client(&ccfg, root, hostname);
    present_ticket(&ccfg);
    uint8_t config_hash[SHA256_LEN];
    webpki_ticket_config_hash(&ccfg, config_hash);
    webpki_ticket_binding(kept.psk, kept.psk_len, config_hash, kept.binding);
    CHECK(!run_quic(&ccfg, &scfg));
    CHECK(ch_quic_state(&client) == CH_ST_FAILED);
    CHECK(ch_quic_error_code(&client) == 0x0100U + alert);
    CHECK(client.t.psk_selected == 0);
    memcpy(kept.binding, binding, sizeof binding);
}

// CH_HELLO_MAX is exact over QUIC: the worst hello this build can emit,
// the pre_shared_key arm with the longest ticket identity and cookie, the
// longest hostname, the widest ALPN offer, CH_TRANSPORT_PARAMS_MAX bytes
// of transport parameters, and both certificate types, which pins beside
// anchors offer, builds at CH_HELLO_MAX and refuses one byte less.
// Without pins it is the 7 bytes of server_certificate_type shorter.
static void test_quic_hello_boundary(void) {
    static uint8_t out[CH_HELLO_MAX];
    static uint8_t identity[CH_TICKET_ID_MAX];
    static uint8_t cookie[HSP_COOKIE_MAX];
    static uint8_t name[CH_HOSTNAME_MAX];
    static uint8_t transport[CH_TRANSPORT_PARAMS_MAX];
    static ch_alpn_protocol widest[CH_ALPN_MAX];
    static uint8_t names[CH_ALPN_MAX][CH_ALPN_NAME_MAX];
    static uint8_t ek[MLKEM_EK_LEN];
    uint8_t pub[32] = {0};
    uint8_t random32[32] = {0};
    for (size_t i = 0; i < sizeof name; i++) {
        name[i] = (i % 64 == 63) ? '.' : 'a';
    }
    for (size_t i = 0; i < CH_ALPN_MAX; i++) {
        memset(names[i], 'a', CH_ALPN_NAME_MAX);
        names[i][0] = (uint8_t)('a' + i);
        widest[i] = (ch_alpn_protocol){names[i], CH_ALPN_NAME_MAX};
    }
    ch_cfg cfg = {0};
    cfg.psk = identity;
    cfg.psk_len = HKDF_HASH_MAX;
    cfg.psk_id = identity;
    cfg.psk_id_len = sizeof identity;
    cfg.resumption = 1;
    cfg.hostname = name;
    cfg.hostname_len = sizeof name;
    cfg.alpn_protocols = widest;
    cfg.alpn_count = CH_ALPN_MAX;
    cfg.transport_params = transport;
    cfg.transport_params_len = sizeof transport;
    cfg.spki_pin_count = 1;
    cfg.anchor_count = 1;
#define BUILD_HELLO(cap)                                                                           \
    hs_build_client_hello(out, (cap), &cfg, ek, NULL, pub, random32, 0, cookie, sizeof cookie)
    CHECK(BUILD_HELLO(CH_HELLO_MAX) == CH_HELLO_MAX);
    CHECK(BUILD_HELLO(CH_HELLO_MAX - 1) == 0);
    cfg.spki_pin_count = 0;
    CHECK(BUILD_HELLO(CH_HELLO_MAX) == CH_HELLO_MAX - 7);
#undef BUILD_HELLO
    CHECK(CH_TX_STAGE == CH_HELLO_MAX);
    CHECK(CH_HELLO_MAX == 2650 + CH_HELLO_AES_SUITES_MAX + CH_HELLO_SHA384_BINDER_MAX);
}

static void test_webpki_resumption(void) {
    ch_cfg scfg;
    ch_cfg ccfg;
    static ch_quic probe;

    // The full handshake: EncryptedExtensions, Certificate,
    // CertificateVerify and Finished, a chain the client verified, and a
    // ticket bound to its hostname and anchors.
    webpki_server(&scfg, ticket_key);
    webpki_client(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(client.t.psk_selected == 0 && server.t.psk_selected == 0);
    CHECK(server.t.sigalg == SIGALG_ECDSA_P256_SHA256);
    CHECK(handshake_messages() == 4);
    check_keys_agree();
    take_ticket();
    CHECK(kept.count == 1 && kept_ticket_bound(&ccfg));

    // That ticket resumes: EncryptedExtensions and Finished alone. The
    // webpki client shares both groups and the server prefers the hybrid,
    // so the resumed key exchange is X25519MLKEM768 (docs/decisions.md
    // 54). The hello offered the certificate path beside the ticket, and
    // the server that selected the ticket names no scheme.
    webpki_client(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    present_ticket(&ccfg);
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(client.t.psk_selected == 1 && server.t.psk_selected == 1 && server.t.sigalg == 0);
    CHECK(handshake_messages() == 2);
    check_keys_agree();
    CHECK(server.t.group == CH_GROUP_X25519MLKEM768);
    CHECK(client.t.group == CH_GROUP_X25519MLKEM768);
    take_ticket();
    CHECK(kept.count == 2 && kept_ticket_bound(&ccfg));

    // A server holding another ticket key passes the ticket over, and the
    // same connection completes as a full handshake that walks the chain.
    webpki_server(&scfg, other_ticket_key);
    webpki_client(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    present_ticket(&ccfg);
    CHECK(run_quic(&ccfg, &scfg));
    CHECK(client.t.psk_selected == 0 && server.t.psk_selected == 0);
    CHECK(server.t.sigalg == SIGALG_ECDSA_P256_SHA256);
    CHECK(handshake_messages() == 4);
    check_keys_agree();

    // That decline checks the chain as a fresh handshake does: the r2
    // leaf names s3.example.test and no other host, and it verifies under
    // root_p384 and not under an anchor that carries its Name over
    // another key.
    check_declined_chain_refused(webpki_corpus_anchors_root_p384, "other.example.test",
                                 ALERT_BAD_CERTIFICATE);
    check_declined_chain_refused(webpki_corpus_anchors_impostor_p384, "s3.example.test",
                                 ALERT_UNKNOWN_CA);

    // What ch_quic_init refuses, with CH_EINVAL and nothing sent: a binding
    // one bit off, the ticket under another hostname, a ticket with no
    // binding, and an external PSK, which has no hostname to bind.
    kept.binding[0] ^= 0x01;
    webpki_client(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    present_ticket(&ccfg);
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    kept.binding[0] ^= 0x01;
    webpki_client(&ccfg, webpki_corpus_anchors_root_p384, "other.example.test");
    present_ticket(&ccfg);
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    webpki_client(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    present_ticket(&ccfg);
    ccfg.ticket_binding = NULL;
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    webpki_client(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    present_ticket(&ccfg);
    ccfg.resumption = 0;
    ccfg.ticket_binding = NULL;
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    // An offer of no protocol, which webpki_cfg_ok admits over TCP and
    // RFC 9001 §8.1 forbids a QUIC client.
    webpki_client(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    ccfg.alpn_protocols = NULL;
    ccfg.alpn_count = 0;
    CHECK(ch_quic_init(&probe, &ccfg) == CH_EINVAL);
    // And the configuration with no ticket at all still initializes.
    webpki_client(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    CHECK(ch_quic_init(&probe, &ccfg) == CH_OK);
}

#endif
