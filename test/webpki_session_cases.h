// The cases test/webpki_session_test.c runs, over its mock server and
// valid_cfg. Included by that file only, after both exist.
#ifndef CH_WEBPKI_SESSION_CASES_H
#define CH_WEBPKI_SESSION_CASES_H

// The anchor rule at its boundaries: 1 to CH_WEBPKI_ANCHOR_MAX entries,
// and every field of every entry set.
static void test_webpki_cfg_anchors(void) {
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    CHECK(sends_client_hello(&cfg));
    cfg = valid_cfg(&s);
    cfg.anchors = NULL;
    CHECK(refused(&cfg));
    cfg = valid_cfg(&s);
    cfg.anchor_count = 0;
    CHECK(refused(&cfg));
    cfg = valid_cfg(&s);
    cfg.anchor_count = 1;
    CHECK(sends_client_hello(&cfg));
    // The last valid count works; the first invalid one fails.
    CHECK(CH_WEBPKI_ANCHOR_MAX == 12);
    cfg = valid_cfg(&s);
    cfg.anchor_count = CH_WEBPKI_ANCHOR_MAX;
    CHECK(sends_client_hello(&cfg));
    cfg = valid_cfg(&s);
    cfg.anchor_count = CH_WEBPKI_ANCHOR_MAX + 1;
    CHECK(refused(&cfg));
    // One field of the last entry of a full table set to NULL or 0, so
    // the rule reads every entry and not only the first.
    for (int field = 0; field < 4; field++) {
        cfg = valid_cfg(&s);
        cfg.anchor_count = CH_WEBPKI_ANCHOR_MAX;
        ch_trust_anchor *last = &anchors[CH_WEBPKI_ANCHOR_MAX - 1];
        last->name = field == 0 ? NULL : last->name;
        last->name_len = field == 1 ? 0 : last->name_len;
        last->spki = field == 2 ? NULL : last->spki;
        last->spki_len = field == 3 ? 0 : last->spki_len;
        CHECK(refused(&cfg));
    }
}

// The clock rule at its boundary: now_seconds 0 is an unset clock and is
// refused; 1, the first second after it, passes the config check and
// the handshake goes on to send its hello.
static void test_webpki_cfg_clock(void) {
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    cfg.now_seconds = 0;
    CHECK(refused(&cfg));
    cfg = valid_cfg(&s);
    cfg.now_seconds = 1;
    CHECK(sends_client_hello(&cfg));
    CHECK(s.hello_len > 0);
}

// Fills name with labels of 63 'a' separated by dots, n bytes in all,
// the last label cut short: a valid shape for any n up to 253.
static void long_hostname(uint8_t *name, size_t n) {
    for (size_t i = 0; i < n; i++) {
        name[i] = (i % 64 == 63) ? '.' : 'a';
    }
}

// The hostname rule: webpki_hostname_ok's shape, at its length boundary.
static void test_webpki_cfg_hostname(void) {
    static uint8_t name[CH_HOSTNAME_MAX + 1];
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    CHECK(CH_HOSTNAME_MAX == 253);
    long_hostname(name, CH_HOSTNAME_MAX);
    cfg.hostname = name;
    cfg.hostname_len = CH_HOSTNAME_MAX;
    CHECK(sends_client_hello(&cfg));
    size_t ext_len = 0;
    CHECK(hello_ext(s.hello, s.hello_len, EXT_SERVER_NAME, &ext_len) != NULL);
    CHECK(ext_len == 2 + 1 + 2 + CH_HOSTNAME_MAX);
    long_hostname(name, CH_HOSTNAME_MAX + 1);
    cfg = valid_cfg(&s);
    cfg.hostname = name;
    cfg.hostname_len = CH_HOSTNAME_MAX + 1;
    CHECK(refused(&cfg));

    static const struct {
        const char *text;
    } bad[] = {{"*.example.test"}, {"s3.exa_mple.test"},  {"127.0.0.1"}, {"a..b"}, {".a.b"},
               {"a.b."},           {"s3.ex\xc3\xa1.test"}};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        cfg = valid_cfg(&s);
        cfg.hostname = (const uint8_t *)bad[i].text;
        cfg.hostname_len = strlen(bad[i].text);
        CHECK(refused(&cfg));
    }
    cfg = valid_cfg(&s);
    cfg.hostname = NULL;
    CHECK(refused(&cfg));
    cfg = valid_cfg(&s);
    cfg.hostname_len = 0;
    CHECK(refused(&cfg));
}

static int test_epoch_load(void *io, uint32_t *value) {
    (void)io;
    *value = 0;
    return 0;
}

static int test_epoch_store(void *io, uint32_t value) {
    (void)io;
    (void)value;
    return 0;
}

// The rules this mode adds against the other modes' fields, and the
// receive floor it raises. A PSK, a pin or an epoch callback beside a
// valid web PKI config is refused, not preferred and not ignored.
static void test_webpki_cfg_other_modes(void) {
    static const uint8_t psk[32] = {1};
    static uint8_t pin[384] = {2};
    pin[sizeof pin - 1] = 1;
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    cfg.psk = psk;
    cfg.psk_len = sizeof psk;
    cfg.psk_id = (const uint8_t *)"d";
    cfg.psk_id_len = 1;
    CHECK(refused(&cfg));
    cfg = valid_cfg(&s);
    cfg.psk_id = (const uint8_t *)"d";
    cfg.psk_id_len = 1;
    CHECK(refused(&cfg));
    cfg = valid_cfg(&s);
    cfg.resumption = 1;
    CHECK(refused(&cfg));
    cfg = valid_cfg(&s);
    cfg.server_pubkey = pin;
    cfg.server_pubkey_len = sizeof pin;
    CHECK(refused(&cfg));
    cfg = valid_cfg(&s);
    cfg.server_pubkey2 = pin;
    cfg.server_pubkey2_len = sizeof pin;
    CHECK(refused(&cfg));
    cfg = valid_cfg(&s);
    cfg.epoch_load = test_epoch_load;
    cfg.epoch_store = test_epoch_store;
    CHECK(refused(&cfg));

    // A length set without its pointer is a PSK or pin config with a
    // field missing, and is refused as the whole field would be.
    cfg = valid_cfg(&s);
    cfg.psk_len = sizeof psk;
    CHECK(refused(&cfg));
    cfg = valid_cfg(&s);
    cfg.psk_id_len = 1;
    CHECK(refused(&cfg));
    cfg = valid_cfg(&s);
    cfg.server_pubkey_len = sizeof pin;
    CHECK(refused(&cfg));
    cfg = valid_cfg(&s);
    cfg.server_pubkey2_len = sizeof pin;
    CHECK(refused(&cfg));

    // The floor is the four-entry flight plus the record that completes
    // it, 12338 bytes, in both KEX builds: the last valid size is the
    // valid config's own buffer. test_rxbuf_floor reassembles that
    // flight at this size and fails it one byte under.
    CHECK(CH_MIN_RXBUF == 4 * (CH_WEBPKI_CERT_MAX + 5) + 8 + REC_OVERHEAD);
    CHECK(CH_MIN_RXBUF == 12338);
    cfg = valid_cfg(&s);
    cfg.buf_len = CH_MIN_RXBUF - 1;
    CHECK(refused(&cfg));

    cfg = valid_cfg(&s);
    cfg.require_pq = 1;
#ifdef CH_KEX_PQ
    CHECK(sends_client_hello(&cfg));
#else
    CHECK(refused(&cfg));
#endif
}

// The ALPN count rule at its boundaries (RFC 7301 §3.1): offering
// nothing is legal and sends no extension, an offer is 1 to
// CH_ALPN_MAX entries, and a count without a list or a list without a
// count is an offer with a field missing.
static void test_webpki_cfg_alpn_count(void) {
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    CHECK(sends_client_hello(&cfg));
    size_t ext_len = 0;
    CHECK(hello_ext(s.hello, s.hello_len, EXT_ALPN, &ext_len) == NULL);

    cfg = valid_cfg(&s);
    cfg.alpn_count = 1;
    CHECK(refused(&cfg));
    cfg = valid_cfg(&s);
    cfg.alpn_protocols = alpn;
    CHECK(refused(&cfg));

    // The last valid count works; the first invalid one fails.
    CHECK(CH_ALPN_MAX == 8);
    cfg = valid_cfg(&s);
    cfg.alpn_protocols = alpn;
    cfg.alpn_count = 1;
    CHECK(sends_client_hello(&cfg));
    cfg = valid_cfg(&s);
    cfg.alpn_protocols = alpn;
    cfg.alpn_count = CH_ALPN_MAX;
    CHECK(sends_client_hello(&cfg));
    cfg = valid_cfg(&s);
    cfg.alpn_protocols = alpn;
    cfg.alpn_count = CH_ALPN_MAX + 1;
    CHECK(refused(&cfg));
}

// An offer of CH_ALPN_MAX names whose last entry the row moves, so the
// name rule reads every entry and not only the first.
static ch_cfg alpn_full_offer(mock_server *s, ch_alpn_protocol last) {
    ch_cfg cfg = valid_cfg(s);
    cfg.alpn_protocols = alpn;
    cfg.alpn_count = CH_ALPN_MAX;
    alpn[CH_ALPN_MAX - 1] = last;
    return cfg;
}

// The name rule at its boundaries: 1 to CH_ALPN_NAME_MAX bytes through
// a non-NULL pointer, and no name repeating an earlier one.
static void test_webpki_cfg_alpn_names(void) {
    static uint8_t name[CH_ALPN_NAME_MAX + 1];
    static const uint8_t h2_copy[] = {'h', '2'};
    memset(name, 'b', sizeof name);
    mock_server s;
    CHECK(CH_ALPN_NAME_MAX == 32);
    // The last valid length works; the first invalid one fails.
    ch_cfg cfg = alpn_full_offer(&s, (ch_alpn_protocol){name, CH_ALPN_NAME_MAX});
    CHECK(sends_client_hello(&cfg));
    cfg = alpn_full_offer(&s, (ch_alpn_protocol){name, CH_ALPN_NAME_MAX + 1});
    CHECK(refused(&cfg));
    // The other end: one byte is the shortest name RFC 7301 admits, and
    // zero bytes is refused, as is a length without its pointer.
    cfg = alpn_full_offer(&s, (ch_alpn_protocol){name, 1});
    CHECK(sends_client_hello(&cfg));
    cfg = alpn_full_offer(&s, (ch_alpn_protocol){name, 0});
    CHECK(refused(&cfg));
    cfg = alpn_full_offer(&s, (ch_alpn_protocol){NULL, 2});
    CHECK(refused(&cfg));
    // A repeated name, compared by its bytes rather than its pointer:
    // h2_copy holds the same two bytes as entry 0 at another address.
    cfg = alpn_full_offer(&s, (ch_alpn_protocol){h2_copy, sizeof h2_copy});
    CHECK(refused(&cfg));
    // A name that only starts like an earlier one is a different name.
    cfg = alpn_full_offer(&s, (ch_alpn_protocol){h2_copy, 1});
    CHECK(sends_client_hello(&cfg));
}

// Reads the hello's ALPN extension back and reports whether its
// ProtocolNameList is exactly the first count names of alpn, in order.
static int hello_alpn_lists(const uint8_t *msg, size_t n, size_t count) {
    size_t ext_len = 0;
    const uint8_t *data = hello_ext(msg, n, EXT_ALPN, &ext_len);
    if (data == NULL) {
        return 0;
    }
    rbuf r;
    rb_init(&r, data, ext_len);
    if (rb_u16(&r) != rb_left(&r)) {
        return 0;
    }
    for (size_t i = 0; i < count; i++) {
        size_t len = rb_u8(&r);
        const uint8_t *name = rb_bytes(&r, len);
        if (name == NULL || len != alpn[i].name_len || memcmp(name, alpn[i].name, len) != 0) {
            return 0;
        }
    }
    return !r.err && rb_left(&r) == 0;
}

// The ALPN extension the hello carries: the exact bytes for the
// two-name offer an HTTP client sends, then the same read back at
// CH_ALPN_MAX names, which is the extension at CH_HELLO_ALPN_MAX bytes.
static void test_webpki_hello_alpn(void) {
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    cfg.alpn_protocols = alpn;
    cfg.alpn_count = 2;
    CHECK(sends_client_hello(&cfg));
    static const uint8_t want[] = {0x00, 0x0c, 0x02, 'h', '2', 0x08, 'h',
                                   't',  't',  'p',  '/', '1', '.',  '1'};
    size_t ext_len = 0;
    const uint8_t *data = hello_ext(s.hello, s.hello_len, EXT_ALPN, &ext_len);
    CHECK(data != NULL && ext_len == sizeof want && memcmp(data, want, sizeof want) == 0);
    CHECK(hello_alpn_lists(s.hello, s.hello_len, 2));

    cfg = valid_cfg(&s);
    cfg.alpn_protocols = alpn;
    cfg.alpn_count = CH_ALPN_MAX;
    CHECK(sends_client_hello(&cfg));
    CHECK(hello_alpn_lists(s.hello, s.hello_len, CH_ALPN_MAX));
}

// The hello a valid config sends: server_name first, carrying the
// hostname as one host_name entry; five signature schemes, the three
// that may sign CertificateVerify before the two PKCS#1 v1.5 ones; and
// no pre_shared_key.
static void test_webpki_hello(void) {
    mock_server s;
    ch_cfg cfg = valid_cfg(&s);
    CHECK(sends_client_hello(&cfg));
    CHECK(hello_first_ext(s.hello, s.hello_len) == EXT_SERVER_NAME);
    size_t ext_len = 0;
    const uint8_t *sni = hello_ext(s.hello, s.hello_len, EXT_SERVER_NAME, &ext_len);
    uint8_t want[2 + 1 + 2 + sizeof host];
    wbuf w;
    wb_init(&w, want, sizeof want);
    wb_u16(&w, (uint16_t)(1 + 2 + sizeof host)); // server_name_list length
    wb_u8(&w, 0);                                // host_name
    wb_u16(&w, sizeof host);
    wb_bytes(&w, host, sizeof host);
    CHECK(!w.err && w.len == sizeof want);
    CHECK(sni != NULL && ext_len == sizeof want && memcmp(sni, want, sizeof want) == 0);

    uint16_t schemes[8] = {0};
    CHECK(hello_sigalgs(s.hello, s.hello_len, schemes, 8) == 5);
    CHECK(schemes[0] == SIGALG_RSA_PSS_RSAE_SHA256 && schemes[1] == SIGALG_ECDSA_P256_SHA256 &&
          schemes[2] == SIGALG_ECDSA_P384_SHA384 && schemes[3] == SIGALG_RSA_PKCS1_SHA256 &&
          schemes[4] == SIGALG_RSA_PKCS1_SHA384);
    CHECK(hello_ext(s.hello, s.hello_len, EXT_PRE_SHARED_KEY, &ext_len) == NULL);
}

// The widest ALPN offer ch_connect accepts: CH_ALPN_MAX names of
// CH_ALPN_NAME_MAX bytes, each starting with its own letter so no two
// repeat. Its extension is CH_HELLO_ALPN_MAX bytes, the term
// CH_HELLO_MAX carries for it.
static void widest_alpn(ch_alpn_protocol *out, uint8_t (*names)[CH_ALPN_NAME_MAX]) {
    for (size_t i = 0; i < CH_ALPN_MAX; i++) {
        memset(names[i], 'a', CH_ALPN_NAME_MAX);
        names[i][0] = (uint8_t)('a' + i);
        out[i].name = names[i];
        out[i].name_len = CH_ALPN_NAME_MAX;
    }
}

// CH_HELLO_MAX is exact in this build, as test_hello_staging_boundary
// holds it in the others: the pre_shared_key arm with the longest
// ticket identity, the longest cookie, the longest hostname and the
// widest ALPN offer builds at CH_HELLO_MAX and refuses one byte less.
// The arm with no psk, the only one ch_connect lets this build send, is
// 351 bytes shorter.
static void test_webpki_hello_boundary(void) {
    static uint8_t out[CH_HELLO_MAX];
    static uint8_t identity[CH_TICKET_ID_MAX];
    static uint8_t cookie[HSP_COOKIE_MAX];
    static uint8_t name[CH_HOSTNAME_MAX];
    static ch_alpn_protocol widest[CH_ALPN_MAX];
    static uint8_t widest_names[CH_ALPN_MAX][CH_ALPN_NAME_MAX];
    uint8_t pub[32] = {0};
    uint8_t random32[32] = {0};
#ifdef CH_KEX_PQ
    static uint8_t ek[MLKEM_EK_LEN];
#endif
    long_hostname(name, sizeof name);
    widest_alpn(widest, widest_names);
    ch_cfg cfg = {0};
    cfg.psk = identity;
    cfg.psk_id = identity;
    cfg.psk_id_len = sizeof identity;
    cfg.resumption = 1;
    cfg.hostname = name;
    cfg.hostname_len = sizeof name;
    cfg.alpn_protocols = widest;
    cfg.alpn_count = CH_ALPN_MAX;
#ifdef CH_KEX_TWO_GROUPS
#define BUILD_HELLO(cap)                                                                           \
    hs_build_client_hello(out, (cap), &cfg, CH_KEX_GROUP, ek, pub, random32, 0xffff, cookie,       \
                          sizeof cookie)
#elif defined(CH_KEX_PQ)
#define BUILD_HELLO(cap)                                                                           \
    hs_build_client_hello(out, (cap), &cfg, ek, pub, random32, 0xffff, cookie, sizeof cookie)
#else
#define BUILD_HELLO(cap)                                                                           \
    hs_build_client_hello(out, (cap), &cfg, pub, random32, 0xffff, cookie, sizeof cookie)
#endif
    size_t psk_arm = BUILD_HELLO(CH_HELLO_MAX);
    CHECK(psk_arm == CH_HELLO_MAX);
    CHECK(BUILD_HELLO(CH_HELLO_MAX - 1) == 0);
    cfg.psk = NULL;
    size_t chain_arm = BUILD_HELLO(CH_HELLO_MAX);
    CHECK(chain_arm == CH_HELLO_MAX - (47 + CH_TICKET_ID_MAX) + 16);
#undef BUILD_HELLO
    CHECK(CH_TX_STAGE == CH_HELLO_MAX);
    CHECK(CH_HELLO_ALPN_MAX == 270);
#ifdef CH_KEX_PQ
    CHECK(CH_HELLO_MAX == 2335);
#else
    CHECK(CH_HELLO_MAX == 1149);
#endif
    (void)printf("webpki hello: %zu bytes with pre_shared_key, %zu without, CH_TX_STAGE %d\n",
                 psk_arm, chain_arm, CH_TX_STAGE);
}

// The chain walk reads the Certificate message, and the mock's one
// entry is eight bytes that are no certificate, so the handshake stops
// there: CH_EPROTO, bad_certificate on the wire, and the whole flight
// read. EncryptedExtensions carried an empty server_name acknowledgement
// before it, which this build admits; the same message with data in the
// acknowledgement is refused there instead.
static void test_webpki_handshake_fails_closed(void) {
    mock_server s;
    ch_tls t;
    ch_cfg cfg = valid_cfg(&s);
    s.answer = 1;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_BAD_CERTIFICATE);
    CHECK(s.rendered && s.queue_off == s.queue_len);
    CHECK(t.state == CH_ST_FAILED);

    // A body of the wrong length gets decode_error (RFC 9846 §6), not
    // the illegal_parameter handshake.c seeds for EncryptedExtensions
    // and not unsupported_extension.
    cfg = valid_cfg(&s);
    s.answer = 1;
    s.sni_data = 1;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(s.alert == ALERT_DECODE_ERROR);
    CHECK(s.queue_off < s.queue_len); // the Certificate record stayed unread
}

// The session reports the server's ALPN selection. The handshake still
// stops at the mock's one bad certificate entry, so these rows read
// ch_tls.alpn_selected after a failed session, as the group and pin
// rows read theirs: the parser wrote it while reading
// EncryptedExtensions, and the failure path does not wipe it.
static void test_webpki_handshake_reports_alpn(void) {
    mock_server s;
    ch_tls t;
    ch_cfg cfg = valid_cfg(&s);
    cfg.alpn_protocols = alpn;
    cfg.alpn_count = 2;
    s.answer = 1;
    s.alpn_pick = alpn_h2;
    s.alpn_pick_len = sizeof alpn_h2;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(t.alpn_selected == 0);
    CHECK(s.alert == ALERT_BAD_CERTIFICATE); // the walk, not the parser

    // The second offered name selects index 1, so the index is the
    // server's choice and not the first entry.
    cfg = valid_cfg(&s);
    cfg.alpn_protocols = alpn;
    cfg.alpn_count = 2;
    s.answer = 1;
    s.alpn_pick = alpn_http11;
    s.alpn_pick_len = sizeof alpn_http11;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(t.alpn_selected == 1);

    // A server that sends no ALPN extension: the handshake goes on and
    // the session reports no selection, so the caller can tell.
    cfg = valid_cfg(&s);
    cfg.alpn_protocols = alpn;
    cfg.alpn_count = 2;
    s.answer = 1;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(t.alpn_selected == CH_ALPN_NONE);
    CHECK(s.alert == ALERT_BAD_CERTIFICATE);

    // A name the client never offered fails the handshake closed with
    // illegal_parameter, before the Certificate record is read.
    cfg = valid_cfg(&s);
    cfg.alpn_protocols = alpn;
    cfg.alpn_count = 1; // "h2" alone
    s.answer = 1;
    s.alpn_pick = alpn_http11;
    s.alpn_pick_len = sizeof alpn_http11;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(t.alpn_selected == CH_ALPN_NONE);
    CHECK(s.alert == ALERT_ILLEGAL_PARAMETER);
    CHECK(s.queue_off < s.queue_len);

    // A config that offered nothing refuses any selection, with the
    // alert for an extension the ClientHello never sent.
    cfg = valid_cfg(&s);
    s.answer = 1;
    s.alpn_pick = alpn_h2;
    s.alpn_pick_len = sizeof alpn_h2;
    CHECK(ch_connect(&t, &cfg) == CH_EPROTO);
    CHECK(t.alpn_selected == CH_ALPN_NONE);
    CHECK(s.alert == ALERT_UNSUPPORTED_EXTENSION);
}

#endif
