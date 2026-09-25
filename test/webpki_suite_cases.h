// The cipher suites a SUITE=aesgcm TRUST=webpki client offers
// (docs/decisions.md entries 45 and 58): TLS_CHACHA20_POLY1305_SHA256
// first, then TLS_AES_128_GCM_SHA256, then TLS_AES_256_GCM_SHA384. The
// rows run against the mock server
// in test/webpki_session_test.c, which bin/webpki_session_aes builds
// with the suite define. A handshake that reaches the mock's one bad
// certificate entry ends in bad_certificate under the handshake keys,
// so that alert is the evidence both sides keyed the same AEAD.
// Included by that file after the mock.
#ifndef CH_TEST_WEBPKI_SUITE_CASES_H
#define CH_TEST_WEBPKI_SUITE_CASES_H
#ifdef CH_CLIENT_AES_SUITES

// The cipher_suites vector of a captured hello equals want: the bytes
// after the legacy_version, the random and the legacy_session_id.
static int hello_suites_are(const uint8_t *hello, size_t n, const uint8_t *want, size_t want_len) {
    rbuf r;
    rb_init(&r, hello, n);
    (void)rb_bytes(&r, 4 + 2 + 32); // header, legacy_version, random
    (void)rb_bytes(&r, rb_u8(&r));  // legacy_session_id
    const uint8_t *suites = rb_bytes(&r, want_len);
    return !r.err && suites != NULL && memcmp(suites, want, want_len) == 0;
}

// The hello lists the three suites, ChaCha20 first and AES-256-GCM last.
static void test_webpki_suites_hello(void) {
    static const uint8_t three[] = {0x00, 0x06, 0x13, 0x03, 0x13, 0x01, 0x13, 0x02};
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    CHECK(sends_client_hello(&cfg));
    CHECK(hello_suites_are(s.hello, s.hello_len, three, sizeof three));
}

// A ServerHello that selects AES-128-GCM: the client keys both
// directions with it, reaches the certificate, and reports the suite.
// The same row with ChaCha20 still reports ChaCha20.
static void test_webpki_suite_aes(void) {
    mock_server s;
    ch_tls t;
    ch_cfg cfg = valid_cfg(&s);
    s.answer = 1;
    s.suite = SUITE_AES_128_GCM_SHA256;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_BAD_CERTIFICATE);
    CHECK(t.suite == SUITE_AES_128_GCM_SHA256);

    // AES-256-GCM runs the transcript and the key schedule on SHA-384,
    // so reaching the certificate under the mock's keys shows both ends
    // derived the same 48-byte secrets.
    cfg = valid_cfg(&s);
    s.answer = 1;
    s.suite = SUITE_AES_256_GCM_SHA384;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_BAD_CERTIFICATE);
    CHECK(t.suite == SUITE_AES_256_GCM_SHA384);

    cfg = valid_cfg(&s);
    s.answer = 1;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_BAD_CERTIFICATE);
    CHECK(t.suite == SUITE_CHACHA20_POLY1305_SHA256);
}

// The suite refusals, each an illegal_parameter before any key exists:
// TLS_AES_128_CCM_SHA256, which this client did not offer (RFC 9846
// §4.2.3, rfc9846.txt:1373-1376), and a ServerHello whose suite differs
// from the retry's (§4.2.4, rfc9846.txt:1489-1491). A ServerHello that
// repeats the retry's AES-128-GCM completes the key exchange under it,
// and so does one that repeats a retry's AES-256-GCM, whose synthetic
// message_hash is a SHA-384 one.
static void test_webpki_suite_refusals(void) {
    mock_server s;
    ch_tls t;
    ch_cfg cfg = valid_cfg(&s);
    s.answer = 1;
    s.suite = 0x1304;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_ILLEGAL_PARAMETER);

    cfg = valid_cfg(&s);
    s.answer = 1;
    s.retry = 1;
    s.retry_cookie = 1;
    s.retry_suite = SUITE_AES_128_GCM_SHA256;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_ILLEGAL_PARAMETER && s.retry_hello_len > 0);

    cfg = valid_cfg(&s);
    s.answer = 1;
    s.retry = 1;
    s.retry_cookie = 1;
    s.retry_suite = SUITE_AES_128_GCM_SHA256;
    s.suite = SUITE_AES_128_GCM_SHA256;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_BAD_CERTIFICATE);
    CHECK(t.suite == SUITE_AES_128_GCM_SHA256);

    cfg = valid_cfg(&s);
    s.answer = 1;
    s.retry = 1;
    s.retry_cookie = 1;
    s.retry_suite = SUITE_AES_256_GCM_SHA384;
    s.suite = SUITE_AES_256_GCM_SHA384;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_BAD_CERTIFICATE);
    CHECK(t.suite == SUITE_AES_256_GCM_SHA384);

    // A retry that named AES-256-GCM and a ServerHello that names
    // AES-128-GCM: the two hashes differ, and the client refuses.
    cfg = valid_cfg(&s);
    s.answer = 1;
    s.retry = 1;
    s.retry_cookie = 1;
    s.retry_suite = SUITE_AES_256_GCM_SHA384;
    s.suite = SUITE_AES_128_GCM_SHA256;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_ILLEGAL_PARAMETER);
}

// A selected PSK binds the suite's hash (rfc9846.txt:2551-2556), driven
// through hsf_accept_server_hello directly, as test/psk_decline_tests.h
// drives the decline. A SHA-384 ticket, 48 bytes, that the server selects
// under TLS_AES_128_GCM_SHA256 is an illegal_parameter abort, and so is a
// SHA-256 ticket selected under TLS_AES_256_GCM_SHA384; each ticket under
// its own suite's hash is accepted.
static int accept_selected_psk(size_t psk_len, uint16_t suite, uint8_t *alert) {
    static const uint8_t psk[SHA384_LEN] = {0x5a};
    static ch_tls session;
    handshake_state h;
    server_hello_info info;
    memset(&session, 0, sizeof session);
    memset(&h, 0, sizeof h);
    memset(&info, 0, sizeof info);
    h.t = &session;
    h.suite = suite;
    session.cfg.psk = psk;
    session.cfg.psk_len = psk_len;
    session.cfg.resumption = 1;
    info.have_share = 1;
    info.group = CH_GROUP_X25519;
    info.suite = suite;
    info.psk_ok = 1;
    info.seen = HSP_SEEN_PRE_SHARED_KEY;
    int rc = hsf_accept_server_hello(&h, &info);
    *alert = h.alert;
    return rc;
}

static void test_webpki_suite_psk_hash(void) {
    uint8_t alert = 0;
    CHECK(accept_selected_psk(SHA384_LEN, SUITE_AES_128_GCM_SHA256, &alert) == CH_EPROTO);
    CHECK(alert == ALERT_ILLEGAL_PARAMETER);
    CHECK(accept_selected_psk(SHA384_LEN, SUITE_CHACHA20_POLY1305_SHA256, &alert) == CH_EPROTO);
    CHECK(alert == ALERT_ILLEGAL_PARAMETER);
    CHECK(accept_selected_psk(SHA256_LEN, SUITE_AES_256_GCM_SHA384, &alert) == CH_EPROTO);
    CHECK(alert == ALERT_ILLEGAL_PARAMETER);
    CHECK(accept_selected_psk(SHA384_LEN, SUITE_AES_256_GCM_SHA384, &alert) == CH_OK);
    CHECK(accept_selected_psk(SHA256_LEN, SUITE_AES_128_GCM_SHA256, &alert) == CH_OK);
}

#endif // CH_CLIENT_AES_SUITES
#endif
