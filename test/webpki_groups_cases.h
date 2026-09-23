// The key exchange groups a TRUST=webpki client offers and the
// HelloRetryRequest rules around them (docs/decisions.md entry 39). A
// KEX=pq build lists X25519MLKEM768 and then x25519 and sends a key
// share for the hybrid alone; a server that lacks the hybrid names
// x25519 in a HelloRetryRequest, and the retry hello carries an x25519
// share. The rows run against the mock server in
// test/webpki_session_test.c, and a handshake that reaches the mock's
// one bad certificate entry ends in bad_certificate under the handshake
// keys, so that alert is the evidence the two sides derived the same
// keys. Included by that file after the mock.
#ifndef CH_TEST_WEBPKI_GROUPS_CASES_H
#define CH_TEST_WEBPKI_GROUPS_CASES_H

// A retry that names the group whose share the hello already carried
// asks for no change, which RFC 9846 §4.3.8 makes an illegal_parameter
// abort (rfc9846.txt:2205-2211). Both builds send a share for
// CH_KEX_GROUP, so the row holds in both, and no retry hello goes out.
static void test_webpki_retry_names_shared_group(void) {
    mock_server s;
    ch_tls t;
    ch_cfg cfg = valid_cfg(&s);
    s.answer = 1;
    s.retry = 1;
    s.retry_group = CH_KEX_GROUP;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_ILLEGAL_PARAMETER);
    CHECK(s.retry_hello_len == 0);
}

#ifdef CH_KEX_TWO_GROUPS
// The supported_groups data of a captured hello equals want.
static int hello_groups_are(const uint8_t *hello, size_t n, const uint8_t *want, size_t want_len) {
    size_t len = 0;
    const uint8_t *groups = hello_ext(hello, n, EXT_SUPPORTED_GROUPS, &len);
    return groups != NULL && len == want_len && memcmp(groups, want, want_len) == 0;
}

// The first hello lists both groups, the hybrid first, and carries one
// key share, for the hybrid. require_pq lists the hybrid alone, which is
// the hello a raw or ca KEX=pq build sends.
static void test_webpki_groups_hello(void) {
    static const uint8_t both[] = {0x00, 0x04, 0x11, 0xec, 0x00, 0x1d};
    static const uint8_t hybrid_only[] = {0x00, 0x02, 0x11, 0xec};
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    CHECK(sends_client_hello(&cfg));
    CHECK(hello_groups_are(s.hello, s.hello_len, both, sizeof both));
    const uint8_t *key = NULL;
    size_t key_len = 0;
    CHECK(hello_share(s.hello, s.hello_len, &key, &key_len) == CH_GROUP_X25519MLKEM768);
    CHECK(key_len == CH_KEX_CLIENT_SHARE);

    cfg = valid_cfg(&s);
    cfg.require_pq = 1;
    CHECK(sends_client_hello(&cfg));
    CHECK(hello_groups_are(s.hello, s.hello_len, hybrid_only, sizeof hybrid_only));
}

// A retry naming x25519, with a cookie and without one. The retry hello
// goes out under legacy_record_version 0x0303 (RFC 9846 §5.1), keeps the
// first hello's random and supported_groups, carries one x25519 share,
// and echoes the cookie when there was one. The handshake then reaches
// the mock's certificate under x25519 keys, and the session reports
// x25519.
static void test_webpki_retry_to_x25519(void) {
    static const uint8_t both[] = {0x00, 0x04, 0x11, 0xec, 0x00, 0x1d};
    for (int cookie = 0; cookie < 2; cookie++) {
        mock_server s;
        ch_tls t;
        ch_cfg cfg = valid_cfg(&s);
        s.answer = 1;
        s.retry = 1;
        s.retry_group = CH_GROUP_X25519;
        s.retry_cookie = cookie;
        CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
        CHECK(s.alert == ALERT_BAD_CERTIFICATE);
        CHECK(t.group == CH_GROUP_X25519);
        CHECK(s.retry_hello_len > 0 && s.retry_record_version == 0x03);
        CHECK(memcmp(s.retry_hello + 6, s.hello + 6, 32) == 0); // the random
        CHECK(hello_groups_are(s.retry_hello, s.retry_hello_len, both, sizeof both));
        const uint8_t *key = NULL;
        size_t key_len = 0;
        CHECK(hello_share(s.retry_hello, s.retry_hello_len, &key, &key_len) == CH_GROUP_X25519);
        CHECK(key_len == X25519_LEN);
        size_t ext_len = 0;
        const uint8_t *echo = hello_ext(s.retry_hello, s.retry_hello_len, EXT_COOKIE, &ext_len);
        CHECK(cookie ? echo != NULL && ext_len == 2 + 4 : echo == NULL);
    }
}

// The refusals the two-group offer adds, each an illegal_parameter
// before any key exists. A retry naming x25519 when require_pq kept it
// off the hello names a group the client did not offer (RFC 9846
// §4.3.8). A ServerHello must select the group of the share the hello
// it answers carried (rfc9846.txt:2222-2237): x25519 without a retry,
// or the hybrid after a retry that named x25519, is refused. A retry
// with neither a cookie nor a key_share asks for no change (§4.2.4).
static void test_webpki_retry_refusals(void) {
    mock_server s;
    ch_tls t;
    ch_cfg cfg = valid_cfg(&s);
    cfg.require_pq = 1;
    s.answer = 1;
    s.retry = 1;
    s.retry_group = CH_GROUP_X25519;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_ILLEGAL_PARAMETER && s.retry_hello_len == 0);

    cfg = valid_cfg(&s);
    s.answer = 1;
    s.sh_group = CH_GROUP_X25519;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_ILLEGAL_PARAMETER);

    cfg = valid_cfg(&s);
    s.answer = 1;
    s.retry = 1;
    s.retry_group = CH_GROUP_X25519;
    s.sh_group = CH_GROUP_X25519MLKEM768;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_ILLEGAL_PARAMETER && s.retry_hello_len > 0);

    cfg = valid_cfg(&s);
    s.answer = 1;
    s.retry = 1;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_ILLEGAL_PARAMETER && s.retry_hello_len == 0);
}
#endif // CH_KEX_TWO_GROUPS

#endif
