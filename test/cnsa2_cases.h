// The cases of test/cnsa2_test.c, after its mock server and valid_cfg.
// Not a standalone translation unit.
#ifndef CH_CNSA2_CASES_H
#define CH_CNSA2_CASES_H

// Runs test_connect on cfg and reports whether it was refused before a
// byte left: CH_EINVAL with no send.
static int refused(const ch_cfg *cfg) {
    ch_tls *t = NULL;
    const mock_server *s = cfg->io;
    return test_connect(&t, cfg) == CH_EINVAL && s->sends == 0;
}

// Runs test_connect on cfg and reports whether it passed the config check:
// the client sent its ClientHello, and recv's failure then returned
// CH_EIO.
static int sends_client_hello(const ch_cfg *cfg) {
    ch_tls *t = NULL;
    const mock_server *s = cfg->io;
    return test_connect(&t, cfg) == CH_EIO && s->m.hello_len > 0;
}

// The profile authenticates by external PSK alone: a pin, or a CA key in
// a CA build, is refused before a byte is sent, beside the PSK or in its
// place, and so is a config with neither. The pin has an RSA-2048
// modulus's shape, 256 bytes and odd, so every other build takes it.
// require_pq is the profile's one behavior and passes.
static void test_cnsa2_cfg(void) {
    static uint8_t pin[256];
    pin[0] = 0xc1;
    pin[sizeof pin - 1] = 1;
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    CHECK(sends_client_hello(&cfg));

    cfg = valid_cfg(&s);
    cfg.server_pubkey = pin;
    cfg.server_pubkey_len = sizeof pin;
    CHECK(refused(&cfg));
    cfg.psk = NULL;
    cfg.psk_len = 0;
    cfg.psk_id = NULL;
    cfg.psk_id_len = 0;
    CHECK(refused(&cfg));
    cfg.server_pubkey = NULL;
    cfg.server_pubkey_len = 0;
    CHECK(refused(&cfg));

    // The PSK length boundary stays the one every build has.
    cfg = valid_cfg(&s);
    cfg.psk_len = CH_PSK_LEN_MIN;
    CHECK(sends_client_hello(&cfg));
    cfg = valid_cfg(&s);
    cfg.psk_len = CH_PSK_LEN_MIN - 1;
    CHECK(refused(&cfg));

    cfg = valid_cfg(&s);
    cfg.require_pq = 1;
    CHECK(sends_client_hello(&cfg));
}

// The hello offers one suite, one group with one share, no signature
// scheme, and a SHA-384 binder in the last extension.
static void test_cnsa2_hello(void) {
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    CHECK(sends_client_hello(&cfg));
    const uint8_t *h = s.m.hello;
    size_t n = s.m.hello_len;
    // The cipher_suites vector follows the version, the random and the
    // empty legacy_session_id: 4 + 2 + 32 + 1 bytes in.
    CHECK(n > 4 + 2 + 32 + 1 + 4 + BINDER_TAIL);
    if (n <= 4 + 2 + 32 + 1 + 4 + BINDER_TAIL) {
        return;
    }
    CHECK(h[39] == 0 && h[40] == 2 && h[41] == 0x13 && h[42] == 0x02);
    size_t len = 0;
    const uint8_t *groups = hello_ext(h, n, EXT_SUPPORTED_GROUPS, &len);
    CHECK(groups != NULL && len == 4 && groups[0] == 0 && groups[1] == 2);
    CHECK(groups != NULL && groups[2] == 0x02 && groups[3] == 0x02);
    hello_share_entry shares[2] = {{0}};
    CHECK(hello_key_shares(h, n, shares, 2) == 1);
    CHECK(shares[0].group == CH_GROUP_MLKEM1024 && shares[0].key_len == MLKEM_EK_LEN);
    CHECK(hello_sigalgs(h, n, NULL, 0) == -1);
    CHECK(hello_first_ext(h, n) == EXT_SUPPORTED_VERSIONS);
    int count = 0;
    CHECK(hello_ext_index(h, n, EXT_PRE_SHARED_KEY, &count) == count - 1 && count > 0);
    const uint8_t *tail = h + n - BINDER_TAIL;
    CHECK(tail[0] == 0 && tail[1] == 1 + SHA384_LEN && tail[2] == SHA384_LEN);
}

// CH_TX_STAGE holds the largest hello the profile emits, and CH_HELLO_MAX
// is its size: at that capacity the worst hello, a resumption with a
// CH_TICKET_ID_MAX identity that answers a HelloRetryRequest with an
// HSP_COOKIE_MAX cookie, is built whole, and one byte less refuses.
static void test_cnsa2_hello_boundary(void) {
    static uint8_t out[CH_HELLO_MAX];
    static uint8_t identity[CH_TICKET_ID_MAX];
    static uint8_t cookie[HSP_COOKIE_MAX];
    static uint8_t ek[MLKEM_EK_LEN];
    uint8_t pub[32] = {0};
    uint8_t random32[32] = {0};
    ch_cfg cfg = {0};
    cfg.psk = identity;
    cfg.psk_id = identity;
    cfg.psk_id_len = sizeof identity;
    static ch_saved_ticket worst;
    worst.ticket.age_add = 0xffffffffU;
    cfg.ticket = &worst;
    CHECK(hs_build_client_hello(out, CH_HELLO_MAX, &cfg, ek, pub, random32, 0xffff, cookie,
                                sizeof cookie) == CH_HELLO_MAX);
    CHECK(hs_build_client_hello(out, CH_HELLO_MAX - 1, &cfg, ek, pub, random32, 0xffff, cookie,
                                sizeof cookie) == 0);
    CHECK(CH_TX_STAGE >= CH_HELLO_MAX);
}

// Two whole handshakes. The first runs under the external PSK and keeps
// the ticket the mock issues; the second resumes it under require_pq,
// which every handshake of the profile satisfies. Each one checks the
// binder, the client Finished and one echoed record, and the session
// reports the profile's group and suite.
static void test_cnsa2_handshake(void) {
    static const uint8_t ping[] = {'p', 'i', 'n', 'g'};
    for (int resume = 0; resume < 2; resume++) {
        mock_server s;
        ch_cfg cfg = valid_cfg(&s);
        s.answer = 1;
        if (resume) {
            cfg.ticket = &saved;
            cfg.require_pq = 1;
        }
        tickets = 0;
        ch_tls *t = NULL;
        CHECK(test_connect(&t, &cfg) == CH_OK);
        CHECK(s.m.binder_ok);
        CHECK(s.m.resumed == resume);
        CHECK(s.m.client_finished_ok);
        CHECK(t->group == CH_GROUP_MLKEM1024);
        CHECK(t->suite == SUITE_AES_256_GCM_SHA384);
        CHECK(t->psk_selected == 1);
        CHECK(ch_write(t, ping, sizeof ping) == CH_OK);
        CHECK(s.echo_len == sizeof ping && memcmp(s.echo, ping, sizeof ping) == 0);
        uint8_t got[16];
        CHECK(ch_read(t, got, sizeof got) == (int)sizeof ping);
        CHECK(memcmp(got, ping, sizeof ping) == 0);
        CHECK(tickets == 1);
        ch_close(t);
    }
}

// A ServerHello that names another suite or another group, or carries a
// ciphertext one byte short, fails the handshake with illegal_parameter
// before a key exists. A parser that took the suite or the group would
// fail too, but later, at the first record and with another alert.
static void test_cnsa2_server_hello_refusals(void) {
    static const uint16_t suites[] = {SUITE_CHACHA20_POLY1305_SHA256, 0x1301};
    for (size_t i = 0; i < sizeof suites / sizeof suites[0]; i++) {
        mock_server s;
        ch_cfg cfg = valid_cfg(&s);
        s.answer = 1;
        s.m.sh_suite = suites[i];
        ch_tls *t = NULL;
        CHECK(test_connect(&t, &cfg) == CH_EPROTO);
        CHECK(ch_alert_sent(t) == ALERT_ILLEGAL_PARAMETER);
    }
    static const uint16_t groups[] = {CH_GROUP_X25519, CH_GROUP_X25519MLKEM768, 0x0201};
    for (size_t i = 0; i < sizeof groups / sizeof groups[0]; i++) {
        mock_server s;
        ch_cfg cfg = valid_cfg(&s);
        s.answer = 1;
        s.m.sh_group = groups[i];
        ch_tls *t = NULL;
        CHECK(test_connect(&t, &cfg) == CH_EPROTO);
        CHECK(ch_alert_sent(t) == ALERT_ILLEGAL_PARAMETER);
    }
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    s.answer = 1;
    s.m.ct_trim = 1;
    ch_tls *t = NULL;
    CHECK(test_connect(&t, &cfg) == CH_EPROTO);
    CHECK(ch_alert_sent(t) == ALERT_ILLEGAL_PARAMETER);
}

#endif
