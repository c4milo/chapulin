// The cipher suites a TRUST=webpki client offers, in its order
// (docs/decisions.md entries 45, 58 and 80), and under SUITE=aesgcm the
// caller's own order, ch_cfg.cipher_suites. The rows run against the mock
// server in test/webpki_session_test.c, which bin/webpki_session_test
// builds without the suite, bin/webpki_session_aes with it in a host object
// and bin/webpki_session_aes_extern with it on AES=extern. A handshake that
// reaches the mock's one bad certificate entry ends in bad_certificate
// under the handshake keys, so that alert is the evidence both sides
// keyed the same AEAD. Included by that file after the mock.
#ifndef CH_TEST_WEBPKI_SUITE_CASES_H
#define CH_TEST_WEBPKI_SUITE_CASES_H

// The cipher_suites vector of a captured hello equals want: the bytes
// after the legacy_version, the random and the legacy_session_id. want
// starts with the vector's length, so a longer vector does not match.
static int hello_suites_are(const uint8_t *hello, size_t n, const uint8_t *want, size_t want_len) {
    rbuf r;
    rb_init(&r, hello, n);
    (void)rb_bytes(&r, 4 + 2 + 32); // header, legacy_version, random
    (void)rb_bytes(&r, rb_u8(&r));  // legacy_session_id
    const uint8_t *suites = rb_bytes(&r, want_len);
    return !r.err && suites != NULL && memcmp(suites, want, want_len) == 0;
}

// The hello lists the build's default order, written out here from the
// build's defines rather than read from suite.h: AES-256-GCM, AES-128-GCM
// and ChaCha20 in a host object whose caller states the AES instructions,
// as TEST_CPU does in a suite build (test/test_cpu.h), ChaCha20,
// AES-128-GCM and AES-256-GCM on AES=extern, and ChaCha20 alone without
// the suite.
static void test_webpki_suites_hello(void) {
#if defined(CH_SUITE_AES_GCM) && defined(CH_CPU_RUNTIME)
    static const uint8_t want[] = {0x00, 0x06, 0x13, 0x02, 0x13, 0x01, 0x13, 0x03};
#elif defined(CH_SUITE_AES_GCM)
    static const uint8_t want[] = {0x00, 0x06, 0x13, 0x03, 0x13, 0x01, 0x13, 0x02};
#else
    static const uint8_t want[] = {0x00, 0x02, 0x13, 0x03};
#endif
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    CHECK(sends_client_hello(&cfg));
    CHECK(hello_suites_are(s.hello, s.hello_len, want, sizeof want));
}

#ifdef CH_CLIENT_AES_SUITES
// Whether ch_connect sent a hello over cfg whose cipher_suites vector
// equals want.
static int offers(ch_cfg *cfg, const uint16_t *list, size_t count, const uint8_t *want,
                  size_t want_len) {
    const mock_server *s = cfg->io;
    cfg->cipher_suites = list;
    cfg->cipher_suite_count = count;
    return sends_client_hello(cfg) && hello_suites_are(s->hello, s->hello_len, want, want_len);
}

// The caller's list, ch_cfg.cipher_suites, at the edge of each rule. One
// suite, two and three are offered as listed, in the caller's order, and
// three distinct suites are the longest list taken. ch_connect refuses,
// before a byte leaves, a fourth entry, a code point the build does not
// hold, a repeat, a count without its list and a list without its count.
static void test_webpki_suite_list(void) {
    static const uint16_t list[4] = {SUITE_AES_128_GCM_SHA256, SUITE_CHACHA20_POLY1305_SHA256,
                                     SUITE_AES_256_GCM_SHA384, SUITE_AES_128_GCM_SHA256};
    static const uint8_t one[] = {0x00, 0x02, 0x13, 0x01};
    static const uint8_t two[] = {0x00, 0x04, 0x13, 0x01, 0x13, 0x03};
    static const uint8_t three[] = {0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02};
    static const uint8_t aes256_alone[] = {0x00, 0x02, 0x13, 0x02};
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    CHECK(offers(&cfg, list, 1, one, sizeof one));
    cfg = valid_cfg(&s);
    CHECK(offers(&cfg, list, 2, two, sizeof two));
    cfg = valid_cfg(&s);
    CHECK(offers(&cfg, list, 3, three, sizeof three));
    cfg = valid_cfg(&s);
    CHECK(offers(&cfg, list + 2, 1, aes256_alone, sizeof aes256_alone));

    static const uint16_t unheld[] = {SUITE_AES_128_GCM_SHA256, 0x1304};
    static const uint16_t repeat[] = {SUITE_AES_256_GCM_SHA384, SUITE_AES_256_GCM_SHA384};
    cfg = valid_cfg(&s);
    cfg.cipher_suites = list;
    cfg.cipher_suite_count = 4;
    CHECK(refused(&cfg));
    cfg.cipher_suites = unheld;
    cfg.cipher_suite_count = 2;
    CHECK(refused(&cfg));
    cfg.cipher_suites = repeat;
    CHECK(refused(&cfg));
    cfg.cipher_suites = NULL;
    CHECK(refused(&cfg));
    cfg.cipher_suites = list;
    cfg.cipher_suite_count = 0;
    CHECK(refused(&cfg));
}

// A ServerHello body that names suite, over an x25519 share, with no
// handshake header, as hsp_parse_server_hello takes it.
static size_t server_hello_body(uint8_t *out, size_t cap, uint16_t suite) {
    wbuf w;
    wb_init(&w, out, cap);
    wb_u16(&w, 0x0303);
    for (int i = 0; i < 32; i++) {
        wb_u8(&w, 0x42);
    }
    wb_u8(&w, 0); // legacy_session_id_echo
    wb_u16(&w, suite);
    wb_u8(&w, 0);
    size_t exts = wb_mark(&w, 2);
    wb_u16(&w, EXT_SUPPORTED_VERSIONS);
    wb_u16(&w, 2);
    wb_u16(&w, TLS13);
    wb_u16(&w, EXT_KEY_SHARE);
    wb_u16(&w, 2 + 2 + X25519_LEN);
    wb_u16(&w, CH_GROUP_X25519);
    wb_u16(&w, X25519_LEN);
    for (int i = 0; i < X25519_LEN; i++) {
        wb_u8(&w, 0x09);
    }
    wb_patch16(&w, exts);
    return w.err ? 0 : w.len;
}

// The parser alone holds a ServerHello to the three suites this client
// can offer, before the flight holds it to the ones the hello listed
// (hs_suite_offered): each of the three parses and is reported, and
// TLS_AES_128_CCM_SHA256, which no build holds, is refused.
static void test_webpki_suite_parser(void) {
    static const uint16_t held[] = {SUITE_CHACHA20_POLY1305_SHA256, SUITE_AES_128_GCM_SHA256,
                                    SUITE_AES_256_GCM_SHA384};
    uint8_t body[128];
    server_hello_info info;
    for (size_t i = 0; i < 3; i++) {
        size_t n = server_hello_body(body, sizeof body, held[i]);
        memset(&info, 0, sizeof info);
        CHECK(n > 0 && hsp_parse_server_hello(body, n, &info, 0) == CH_OK);
        CHECK(info.suite == held[i]);
    }
    size_t n = server_hello_body(body, sizeof body, 0x1304);
    memset(&info, 0, sizeof info);
    CHECK(n > 0 && hsp_parse_server_hello(body, n, &info, 0) == CH_EPROTO);
}

// The client takes back only a suite its hello listed. With AES-128-GCM
// listed alone, a ServerHello that names ChaCha20 or AES-256-GCM, which
// the build holds, and a retry that names ChaCha20 are each an
// illegal_parameter abort before any key exists, and the retry gets no
// second hello (rfc9846.txt:1373-1376, 1484-1485). A ServerHello that
// names AES-128-GCM completes the key exchange under it.
static void test_webpki_suite_list_takes_back(void) {
    static const uint16_t aes128[] = {SUITE_AES_128_GCM_SHA256};
    mock_server s;
    ch_tls t;
    ch_cfg cfg = valid_cfg(&s);
    cfg.cipher_suites = aes128;
    cfg.cipher_suite_count = 1;
    s.answer = 1;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_ILLEGAL_PARAMETER);

    cfg = valid_cfg(&s);
    cfg.cipher_suites = aes128;
    cfg.cipher_suite_count = 1;
    s.answer = 1;
    s.suite = SUITE_AES_256_GCM_SHA384;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_ILLEGAL_PARAMETER);

    cfg = valid_cfg(&s);
    cfg.cipher_suites = aes128;
    cfg.cipher_suite_count = 1;
    s.answer = 1;
    s.retry = 1;
    s.retry_cookie = 1;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_ILLEGAL_PARAMETER && s.hrr_len > 0 && s.retry_hello_len == 0);

    cfg = valid_cfg(&s);
    cfg.cipher_suites = aes128;
    cfg.cipher_suite_count = 1;
    s.answer = 1;
    s.suite = SUITE_AES_128_GCM_SHA256;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_BAD_CERTIFICATE && t.suite == SUITE_AES_128_GCM_SHA256);
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
#ifdef CH_CPU_RUNTIME
    session.cfg.cpu = TEST_CPU;
#endif
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

#if defined(CH_CPU_RUNTIME) && defined(CH_SUITE_AES_GCM)
// The client's offer under each value of the AES bit, in the host suite
// build bin/webpki_session_aes (docs/decisions.md 81 and 89): with
// CH_CPU_CONSTANT_TIME_AES it offers AES-256-GCM, AES-128-GCM and
// ChaCha20, and without it ChaCha20 alone. test/webpki_session_cpu.h holds
// the values ch_connect refuses.
static void test_webpki_runtime_answers(void) {
    static const uint8_t aes_first[] = {0x00, 0x06, 0x13, 0x02, 0x13, 0x01, 0x13, 0x03};
    static const uint8_t chacha_alone[] = {0x00, 0x02, 0x13, 0x03};
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    cfg.cpu = CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES;
    CHECK(sends_client_hello(&cfg));
    CHECK(hello_suites_are(s.hello, s.hello_len, aes_first, sizeof aes_first));
    cfg = valid_cfg(&s);
    cfg.cpu = CH_CPU_PROBED;
    CHECK(sends_client_hello(&cfg));
    CHECK(hello_suites_are(s.hello, s.hello_len, chacha_alone, sizeof chacha_alone));
}

// A client whose caller did not state the AES instructions: a list that
// names an AES-GCM suite is refused before a byte leaves, ChaCha20 alone
// is offered, and a ServerHello or a HelloRetryRequest that selects
// AES-128-GCM, which the hello did not list, is an illegal_parameter
// abort (rfc9846.txt:1373-1376, 1484-1485), the retry before any second
// hello.
static void test_webpki_runtime_without_aes(void) {
    static const uint16_t aes128[] = {SUITE_AES_128_GCM_SHA256};
    static const uint16_t chacha_then_aes[] = {SUITE_CHACHA20_POLY1305_SHA256,
                                               SUITE_AES_256_GCM_SHA384};
    static const uint16_t chacha[] = {SUITE_CHACHA20_POLY1305_SHA256};
    static const uint8_t chacha_alone[] = {0x00, 0x02, 0x13, 0x03};
    mock_server s;
    ch_tls t;
    ch_cfg cfg = valid_cfg(&s);
    cfg.cpu = CH_CPU_PROBED;
    cfg.cipher_suites = aes128;
    cfg.cipher_suite_count = 1;
    CHECK(refused(&cfg));
    cfg.cipher_suites = chacha_then_aes;
    cfg.cipher_suite_count = 2;
    CHECK(refused(&cfg));
    cfg = valid_cfg(&s);
    cfg.cpu = CH_CPU_PROBED;
    CHECK(offers(&cfg, chacha, 1, chacha_alone, sizeof chacha_alone));

    cfg = valid_cfg(&s);
    cfg.cpu = CH_CPU_PROBED;
    s.answer = 1;
    s.suite = SUITE_AES_128_GCM_SHA256;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_ILLEGAL_PARAMETER);

    cfg = valid_cfg(&s);
    cfg.cpu = CH_CPU_PROBED;
    s.answer = 1;
    s.retry = 1;
    s.retry_cookie = 1;
    s.retry_suite = SUITE_AES_128_GCM_SHA256;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_ILLEGAL_PARAMETER && s.retry_hello_len == 0);
}
#endif

#endif // CH_CLIENT_AES_SUITES
#endif
