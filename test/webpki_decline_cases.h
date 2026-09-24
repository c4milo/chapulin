// The rows of test/webpki_resume_test.c that offer the certificate path
// beside the ticket (docs/decisions.md 55): the resuming hello's bytes, a
// server that declines the ticket and authenticates with the r2 corpus
// chain in the same connection, the chain checks that decline still
// runs, a HelloRetryRequest before either answer, and the ServerHello
// handler on its own. Included after test/webpki_resume_cases.h, whose
// configuration helpers it reads.
#ifndef CH_TEST_WEBPKI_DECLINE_CASES_H
#define CH_TEST_WEBPKI_DECLINE_CASES_H

#include "psk_decline_tests.h"

// The binding webpki_ticket.h gives psk under cfg's hostname, anchors and
// pins, as on_ticket would have handed it over.
static void bind_ticket(const ch_cfg *cfg, const uint8_t *psk, uint8_t out[SHA256_LEN]) {
    uint8_t hash[SHA256_LEN];
    webpki_ticket_config_hash(cfg, hash);
    webpki_ticket_binding(psk, hash, out);
}

// A configuration that verifies the r2 chain, root_anchor and hostname as
// r2_trust takes them, presenting ticket_psk bound to it into binding.
static ch_cfg chain_cfg(const webpki_corpus_anchor *root_anchor, const char *hostname,
                        uint8_t binding[SHA256_LEN]) {
    ch_cfg cfg = base_cfg();
    r2_trust(&cfg, root_anchor, hostname);
    bind_ticket(&cfg, ticket_psk, binding);
    present(&cfg, ticket_psk, binding);
    memcpy(mock.psk, ticket_psk, SHA256_LEN);
    return cfg;
}

// With SPKI pins beside the anchors the resuming hello offers both
// certificate types too, the raw key first, ahead of pre_shared_key.
static void test_resumed_hello_offers_certificates(void) {
    uint8_t binding[SHA256_LEN];
    static const uint8_t pin[1][SHA256_LEN] = {{0x70}};
    ch_cfg cfg = base_cfg();
    cfg.spki_pins = (const uint8_t *)pin;
    cfg.spki_pin_count = 1;
    bind_ticket(&cfg, ticket_psk, binding);
    present(&cfg, ticket_psk, binding);
    CHECK(resumes(&cfg, ticket_psk));
    CHECK(certificate_path_then_ticket(mock.hello, mock.hello_len, 1));
    size_t len = 0;
    const uint8_t *types = hello_ext(mock.hello, mock.hello_len, EXT_SERVER_CERTIFICATE_TYPE, &len);
    CHECK(types != NULL && len == 3 && types[0] == 2 && types[1] == CH_CERT_TYPE_RAW_PUBLIC_KEY &&
          types[2] == CH_CERT_TYPE_X509);
    CHECK(session_tls()->psk_selected == 1);
}

// A server that does not select the ticket: the handshake goes on as a
// full one in the same connection. The mock's keys start from the early
// secret of no PSK, so a client that kept the PSK's cannot open its
// records; the chain walk runs against the anchor, the hostname and the
// clock; and the session reports no resumption. The ticket the session
// then receives is bound like any other.
static void test_server_declines_ticket(void) {
    uint8_t binding[SHA256_LEN];
    ch_cfg cfg = chain_cfg(webpki_corpus_anchors_root_p384, "s3.example.test", binding);
    CHECK(connect_session(&cfg) == CH_OK);
    CHECK(session_tls()->psk_selected == 1 && mock.certificates == 0);

    cfg = chain_cfg(webpki_corpus_anchors_root_p384, "s3.example.test", binding);
    mock.decline = 1;
    CHECK(connect_session(&cfg) == CH_OK);
    CHECK(session_tls()->state == CH_ST_CONNECTED);
    CHECK(session_tls()->psk_selected == 0);
    CHECK(session_tls()->server_cert_type == CH_CERT_TYPE_X509);
    CHECK(mock.certificates == 1 && mock.hellos == 1 && mock.binders_ok == 1);
    CHECK(certificate_path_then_ticket(mock.hello, mock.hello_len, 0));
    push_ticket(&mock);
    uint8_t got[8];
    CHECK(ch_read(session_tls(), got, sizeof got) == 2 && memcmp(got, "ok", 2) == 0);
    uint8_t want[SHA256_LEN];
    bind_ticket(&cfg, received.psk, want);
    CHECK(received.count == 1 && memcmp(received.binding, want, SHA256_LEN) == 0);
}

// A decline runs every check a fresh handshake runs: the r2 chain names
// s3.example.test and no other host, and it verifies under root_p384 and
// not under an anchor that carries that root's Name over another key. A
// ServerHello whose pre_shared_key names an identity this client never
// offered is no decline at all.
static void test_decline_checks_the_chain(void) {
    uint8_t binding[SHA256_LEN];
    ch_cfg cfg = chain_cfg(webpki_corpus_anchors_root_p384, "other.example.test", binding);
    mock.decline = 1;
    CHECK(connect_session(&cfg) == CH_EAUTH);
    CHECK(session_tls()->state == CH_ST_FAILED && session_alert(&mock) == ALERT_BAD_CERTIFICATE);
    CHECK(mock.certificates == 1);

    cfg = chain_cfg(webpki_corpus_anchors_impostor_p384, "s3.example.test", binding);
    mock.decline = 1;
    CHECK(connect_session(&cfg) == CH_EAUTH);
    CHECK(session_tls()->state == CH_ST_FAILED && session_alert(&mock) == ALERT_UNKNOWN_CA);

    cfg = chain_cfg(webpki_corpus_anchors_root_p384, "s3.example.test", binding);
    mock.identity = 1;
    CHECK(connect_session(&cfg) == CH_EPROTO);
    CHECK(session_tls()->state == CH_ST_FAILED && session_alert(&mock) == ALERT_ILLEGAL_PARAMETER);
}

// A HelloRetryRequest first. The retry hello offers the ticket again with
// the same extensions and a binder computed over the replaced transcript,
// which the mock checks against its own; then the server resumes, or
// declines and authenticates with the chain.
static void test_retry_then_resume_or_decline(void) {
    uint8_t binding[SHA256_LEN];
    ch_cfg cfg = chain_cfg(webpki_corpus_anchors_root_p384, "s3.example.test", binding);
    mock.retry = 1;
    CHECK(connect_session(&cfg) == CH_OK);
    CHECK(session_tls()->psk_selected == 1 && mock.certificates == 0);
    CHECK(mock.hellos == 2 && mock.binders_ok == 2);
    CHECK(certificate_path_then_ticket(mock.hello, mock.hello_len, 0));
    size_t len = 0;
    CHECK(hello_ext(mock.hello, mock.hello_len, EXT_COOKIE, &len) != NULL);

    cfg = chain_cfg(webpki_corpus_anchors_root_p384, "s3.example.test", binding);
    mock.retry = 1;
    mock.decline = 1;
    CHECK(connect_session(&cfg) == CH_OK);
    CHECK(session_tls()->psk_selected == 0 && mock.certificates == 1);
    CHECK(mock.hellos == 2 && mock.binders_ok == 2);
}

#endif
