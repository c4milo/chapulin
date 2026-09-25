// The key exchange groups a TRUST=webpki client offers and the
// HelloRetryRequest rules around them (docs/decisions.md entry 53). Every
// webpki build lists X25519MLKEM768 and then x25519 and sends a key share
// for each, the x25519 one over the x25519 half of the hybrid one, so a
// server picks either without a retry, and a retry that names a group
// names one already shared. The rows run against the mock server in
// test/webpki_session_test.c, and a handshake that reaches the mock's
// one bad certificate entry ends in bad_certificate under the handshake
// keys, so that alert is the evidence the two sides derived the same
// keys. Included by that file after the mock.
#ifndef CH_TEST_WEBPKI_GROUPS_CASES_H
#define CH_TEST_WEBPKI_GROUPS_CASES_H

// The supported_groups data of a captured hello equals want.
static int hello_groups_are(const uint8_t *hello, size_t n, const uint8_t *want, size_t want_len) {
    size_t len = 0;
    const uint8_t *groups = hello_ext(hello, n, EXT_SUPPORTED_GROUPS, &len);
    return groups != NULL && len == want_len && memcmp(groups, want, want_len) == 0;
}

// The key_share of a captured hello is the two-share offer: the hybrid
// entry, 1216 bytes of ML-KEM encapsulation key then x25519 value, and
// the x25519 entry, whose 32 bytes are the hybrid entry's x25519 half
// (RFC 9954 §3.2). The extension is exactly those two entries.
static int hello_shares_both(const uint8_t *hello, size_t n) {
    hello_share_entry shares[3] = {{0}};
    size_t ext_len = 0;
    int ok = hello_key_shares(hello, n, shares, 3) == 2 &&
             hello_ext(hello, n, EXT_KEY_SHARE, &ext_len) != NULL &&
             ext_len == 2 + (2 + 2 + CH_HYBRID_CLIENT_SHARE) + (2 + 2 + X25519_LEN);
    return ok && shares[0].group == CH_GROUP_X25519MLKEM768 &&
           shares[0].key_len == CH_HYBRID_CLIENT_SHARE && shares[1].group == CH_GROUP_X25519 &&
           shares[1].key_len == X25519_LEN &&
           memcmp(shares[1].key, shares[0].key + MLKEM_EK_LEN, X25519_LEN) == 0;
}

// The first hello lists both groups, the hybrid first, and carries a key
// share for each in the same order (RFC 9846 §4.3.8,
// rfc9846.txt:2161-2163).
static void test_webpki_groups_hello(void) {
    static const uint8_t both[] = {0x00, 0x04, 0x11, 0xec, 0x00, 0x1d};
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    CHECK(sends_client_hello(&cfg));
    CHECK(hello_groups_are(s.hello, s.hello_len, both, sizeof both));
    CHECK(hello_shares_both(s.hello, s.hello_len));
}

// require_pq lists the hybrid alone and shares it alone, which is the
// hello a raw or ca KEX=pq build sends.
static void test_webpki_groups_hello_require_pq(void) {
    static const uint8_t hybrid_only[] = {0x00, 0x02, 0x11, 0xec};
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    cfg.require_pq = 1;
    CHECK(sends_client_hello(&cfg));
    CHECK(hello_groups_are(s.hello, s.hello_len, hybrid_only, sizeof hybrid_only));
    hello_share_entry shares[2] = {{0}};
    CHECK(hello_key_shares(s.hello, s.hello_len, shares, 2) == 1);
    CHECK(shares[0].group == CH_GROUP_X25519MLKEM768 &&
          shares[0].key_len == CH_HYBRID_CLIENT_SHARE);
    size_t key_len = 0;
    CHECK(hello_key_share(s.hello, s.hello_len, CH_GROUP_X25519, &key_len) == NULL);
}

// A ServerHello may select either group, in one round trip: the
// handshake reaches the mock's certificate under keys from that group's
// exchange, the session reports it, and no retry hello goes out.
static void test_webpki_selects_either_group(void) {
    static const uint16_t groups[] = {CH_GROUP_X25519MLKEM768, CH_GROUP_X25519};
    for (size_t i = 0; i < sizeof groups / sizeof groups[0]; i++) {
        mock_server s;
        ch_tls t;
        ch_cfg cfg = valid_cfg(&s);
        s.answer = 1;
        s.sh_group = groups[i];
        CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
        CHECK(s.alert == ALERT_BAD_CERTIFICATE);
        CHECK(t.group == groups[i]);
        CHECK(s.retry_hello_len == 0);
    }
}

// require_pq kept x25519 off the hello, so a ServerHello that selects it
// selects a group the client never offered: illegal_parameter (RFC 9846
// §4.3.8), before any key exists, with the group still reported. The
// hybrid completes as it does without the flag.
static void test_webpki_require_pq_refuses_x25519(void) {
    mock_server s;
    ch_tls t;
    ch_cfg cfg = valid_cfg(&s);
    cfg.require_pq = 1;
    s.answer = 1;
    s.sh_group = CH_GROUP_X25519;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_ILLEGAL_PARAMETER);
    CHECK(t.group == CH_GROUP_X25519);

    cfg = valid_cfg(&s);
    cfg.require_pq = 1;
    s.answer = 1;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_BAD_CERTIFICATE);
    CHECK(t.group == CH_GROUP_X25519MLKEM768);
}

// The last valid retry: a cookie and no key_share. The retry hello goes
// out under legacy_record_version 0x0303 (RFC 9846 §5.1), keeps the first
// hello's random, groups and both key shares, and echoes the cookie
// (§4.2.2). The ServerHello that answers it may then select either group.
static void test_webpki_cookie_retry(void) {
    static const uint16_t groups[] = {CH_GROUP_X25519MLKEM768, CH_GROUP_X25519};
    for (size_t i = 0; i < sizeof groups / sizeof groups[0]; i++) {
        mock_server s;
        ch_tls t;
        ch_cfg cfg = valid_cfg(&s);
        s.answer = 1;
        s.retry = 1;
        s.retry_cookie = 1;
        s.sh_group = groups[i];
        CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
        CHECK(s.alert == ALERT_BAD_CERTIFICATE);
        CHECK(t.group == groups[i]);
        CHECK(s.retry_hello_len > 0 && s.retry_record_version == 0x03);
        CHECK(memcmp(s.retry_hello + 6, s.hello + 6, 32) == 0); // the random
        size_t first_len = 0;
        size_t retry_len = 0;
        const uint8_t *first = hello_ext(s.hello, s.hello_len, EXT_KEY_SHARE, &first_len);
        const uint8_t *again =
            hello_ext(s.retry_hello, s.retry_hello_len, EXT_KEY_SHARE, &retry_len);
        CHECK(hello_shares_both(s.retry_hello, s.retry_hello_len));
        CHECK(first != NULL && again != NULL && first_len == retry_len &&
              memcmp(first, again, first_len) == 0);
        size_t ext_len = 0;
        const uint8_t *echo = hello_ext(s.retry_hello, s.retry_hello_len, EXT_COOKIE, &ext_len);
        CHECK(echo != NULL && ext_len == 2 + 4);
    }
}

// The first invalid retries: every retry that names a group. Both groups
// the hello lists already have a share in it, so naming either asks for
// a share the hello carried, and under require_pq x25519 is a group it
// never listed; RFC 9846 §4.3.8 makes both an illegal_parameter abort
// (rfc9846.txt:2205-2212), with a cookie beside the group or without
// one, and no retry hello goes out. A retry with neither a group nor a
// cookie asks for no change, the same alert under §4.2.4.
static void test_webpki_retry_names_a_group(void) {
    static const uint16_t groups[] = {CH_GROUP_X25519MLKEM768, CH_GROUP_X25519};
    for (size_t i = 0; i < 2 * sizeof groups / sizeof groups[0]; i++) {
        mock_server s;
        ch_tls t;
        ch_cfg cfg = valid_cfg(&s);
        s.answer = 1;
        s.retry = 1;
        s.retry_group = groups[i / 2];
        s.retry_cookie = (int)(i % 2);
        CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
        CHECK(s.alert == ALERT_ILLEGAL_PARAMETER && s.retry_hello_len == 0);
    }

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
    s.retry = 1;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_ILLEGAL_PARAMETER && s.retry_hello_len == 0);
}

// Whether all 64 bytes of a seed are zero.
static int seed_wiped(const uint8_t dz[64]) {
    static const uint8_t zero[64] = {0};
    return memcmp(dz, zero, sizeof zero) == 0;
}

// The key exchange a ServerHello selected, run on a handshake_state the
// test can read afterwards, which the blocking driver's frame hides. An
// x25519 selection leaves the ML-KEM key pair unused, and its seed is
// zero once the exchange has run; a hybrid selection consumes the seed
// and leaves it zero too.
static void test_webpki_x25519_wipes_the_seed(void) {
    static const uint8_t ct[MLKEM_CT_LEN] = {0x33};
    static const uint16_t groups[] = {CH_GROUP_X25519, CH_GROUP_X25519MLKEM768};
    for (size_t i = 0; i < sizeof groups / sizeof groups[0]; i++) {
        mock_server s;
        ch_tls t;
        memset(&t, 0, sizeof t);
        t.cfg = valid_cfg(&s);
        handshake_state h;
        memset(&h, 0, sizeof h);
        h.t = &t;
        hsf_begin(&h);
        CHECK(!seed_wiped(h.dz));

        server_hello_info info;
        memset(&info, 0, sizeof info);
        info.group = groups[i];
        info.have_share = 1;
        x25519_base(info.server_pub, server_scalar);
        if (groups[i] == CH_GROUP_X25519MLKEM768) {
            info.server_ct = ct;
        }
#ifdef CH_SUITE_AES_GCM
        // The suite hsf_read_server_hello would have taken, which names
        // the hash the secrets derive at.
        h.suite = SUITE_CHACHA20_POLY1305_SHA256;
#endif
        CHECK(hsf_derive_handshake_secrets(&h, &info) == CH_OK);
        CHECK(seed_wiped(h.dz));
    }
}

#endif
