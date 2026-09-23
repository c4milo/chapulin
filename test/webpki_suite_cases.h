// The cipher suites a SUITE=aesgcm TRUST=webpki client offers
// (docs/decisions.md entry 45): TLS_CHACHA20_POLY1305_SHA256 first and
// TLS_AES_128_GCM_SHA256 after it. The rows run against the mock server
// in test/webpki_session_test.c, which bin/webpki_session_aes builds
// with the suite define. A handshake that reaches the mock's one bad
// certificate entry ends in bad_certificate under the handshake keys,
// so that alert is the evidence both sides keyed the same AEAD.
// Included by that file after the mock.
#ifndef CH_TEST_WEBPKI_SUITE_CASES_H
#define CH_TEST_WEBPKI_SUITE_CASES_H
#ifdef CH_CLIENT_TWO_SUITES

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

// The hello lists both suites, ChaCha20 first.
static void test_webpki_suites_hello(void) {
    static const uint8_t both[] = {0x00, 0x04, 0x13, 0x03, 0x13, 0x01};
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    CHECK(sends_client_hello(&cfg));
    CHECK(hello_suites_are(s.hello, s.hello_len, both, sizeof both));
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

    cfg = valid_cfg(&s);
    s.answer = 1;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_BAD_CERTIFICATE);
    CHECK(t.suite == SUITE_CHACHA20_POLY1305_SHA256);
}

// The suite refusals, each an illegal_parameter before any key exists:
// TLS_AES_256_GCM_SHA384, which this client did not offer (RFC 9846
// §4.2.3, rfc9846.txt:1373-1376), and a ServerHello whose suite differs
// from the retry's (§4.2.4, rfc9846.txt:1489-1491). A ServerHello that
// repeats the retry's AES-128-GCM completes the key exchange under it.
static void test_webpki_suite_refusals(void) {
    mock_server s;
    ch_tls t;
    ch_cfg cfg = valid_cfg(&s);
    s.answer = 1;
    s.suite = 0x1302;
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
}

#endif // CH_CLIENT_TWO_SUITES
#endif
