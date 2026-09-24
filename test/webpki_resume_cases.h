// The resumption rows of test/webpki_resume_test.c: the binding's
// layout, the shape of a presented ticket, the hostname and anchors it
// names, and a resumed handshake from end to end. Included after
// webpki_resume_session.h.
#ifndef CH_TEST_WEBPKI_RESUME_CASES_H
#define CH_TEST_WEBPKI_RESUME_CASES_H

static uint8_t rxbuf[CH_MIN_RXBUF];
static mock_server mock;
static const uint8_t anchor_der[] = {0x30, 0x00};
static const uint8_t other_spki[] = {0x30, 0x01, 0x00};
static ch_trust_anchor anchors[3];
static const uint8_t host[] = {'s', '3', '.', 'e', 'x', 'a', 'm', 'p',
                               'l', 'e', '.', 't', 'e', 's', 't'};
static const uint8_t host_capitals[] = {'S', '3', '.', 'E', 'x', 'a', 'm', 'p',
                                        'l', 'e', '.', 'T', 'E', 'S', 'T'};
static const uint8_t other_host[] = {'s', '3', '.', 'e', 'x', 'a', 'm',
                                     'p', 'l', 'e', '.', 'o', 'r', 'g'};
static uint8_t ticket_psk[SHA256_LEN + 1]; // 0x00..0x20; the byte past SHA256_LEN is a length row
static uint8_t ticket_id[CH_TICKET_ID_MAX + 1];

// The binding of ticket_psk under base_cfg's hostname and two anchors,
// computed outside this tree: Python's hashlib and hmac over the layout
// webpki_ticket.h states.
static const uint8_t known_binding[SHA256_LEN] = {
    0x2f, 0x83, 0xf7, 0xef, 0x8f, 0x96, 0x3b, 0x28, 0x6f, 0x65, 0x07, 0xcf, 0x7c, 0x0c, 0xb9, 0x55,
    0x6b, 0xed, 0x74, 0x2d, 0xc5, 0x94, 0x2b, 0xb0, 0xd0, 0xcd, 0x47, 0xb6, 0x72, 0xa1, 0x3d, 0x69};

// A valid TRUST=webpki config with no PSK: two anchors, a hostname and a
// clock. It resets the mock and the received ticket.
static ch_cfg base_cfg(void) {
    for (size_t i = 0; i < sizeof anchors / sizeof anchors[0]; i++) {
        anchors[i] =
            (ch_trust_anchor){anchor_der, sizeof anchor_der, anchor_der, sizeof anchor_der};
    }
    for (size_t i = 0; i < sizeof ticket_psk; i++) {
        ticket_psk[i] = (uint8_t)i;
    }
    memset(ticket_id, 'i', sizeof ticket_id);
    memset(&mock, 0, sizeof mock);
    memset(&received, 0, sizeof received);
    ch_cfg cfg = {0};
    cfg.buf = rxbuf;
    cfg.buf_len = sizeof rxbuf;
    cfg.send = mock_send;
    cfg.recv = mock_recv;
    cfg.io = &mock;
    cfg.on_ticket = keep_ticket;
    cfg.anchors = anchors;
    cfg.anchor_count = 2;
    cfg.hostname = host;
    cfg.hostname_len = sizeof host;
    cfg.now_seconds = 1789000000U;
    return cfg;
}

// Presents a ticket: psk as the PSK, an eight-byte identity, and binding.
static void present(ch_cfg *cfg, const uint8_t *psk, const uint8_t *binding) {
    cfg->psk = psk;
    cfg->psk_len = SHA256_LEN;
    cfg->psk_id = ticket_id;
    cfg->psk_id_len = 8;
    cfg->resumption = 1;
    cfg->ticket_binding = binding;
}

// Whether the config was refused before a byte left: CH_EINVAL, no send.
static int refused(const ch_cfg *cfg) {
    return connect_session(cfg) == CH_EINVAL && mock.sends == 0;
}

// Whether the config passed and the handshake resumed under server_psk.
static int resumes(const ch_cfg *cfg, const uint8_t *server_psk) {
    memcpy(mock.psk, server_psk, SHA256_LEN);
    return connect_session(cfg) == CH_OK;
}

static void test_binding_known_answer(void) {
    ch_cfg cfg = base_cfg();
    uint8_t hash[SHA256_LEN];
    uint8_t binding[SHA256_LEN];
    webpki_ticket_config_hash(&cfg, hash);
    webpki_ticket_binding(ticket_psk, hash, binding);
    CHECK(memcmp(binding, known_binding, SHA256_LEN) == 0);
    // Capitals hash as their lower case, so the binding does not move.
    cfg.hostname = host_capitals;
    webpki_ticket_config_hash(&cfg, hash);
    webpki_ticket_binding(ticket_psk, hash, binding);
    CHECK(memcmp(binding, known_binding, SHA256_LEN) == 0);
}

static void test_ticket_shape(void) {
    ch_cfg cfg = base_cfg();
    present(&cfg, ticket_psk, known_binding);
    CHECK(resumes(&cfg, ticket_psk));
    // The PSK is the SHA256_LEN bytes ks_res_psk writes, no fewer or more.
    cfg = base_cfg();
    present(&cfg, ticket_psk, known_binding);
    cfg.psk_len = SHA256_LEN - 1;
    CHECK(refused(&cfg));
    cfg.psk_len = SHA256_LEN + 1;
    CHECK(refused(&cfg));
    // The identity is 1 to CH_TICKET_ID_MAX bytes.
    cfg = base_cfg();
    present(&cfg, ticket_psk, known_binding);
    cfg.psk_id_len = CH_TICKET_ID_MAX;
    CHECK(resumes(&cfg, ticket_psk));
    cfg = base_cfg();
    present(&cfg, ticket_psk, known_binding);
    cfg.psk_id_len = CH_TICKET_ID_MAX + 1;
    CHECK(refused(&cfg));
    cfg.psk_id_len = 0;
    CHECK(refused(&cfg));
    // A field missing: no identity, no PSK, or no binding.
    cfg.psk_id_len = 8;
    cfg.psk_id = NULL;
    CHECK(refused(&cfg));
    cfg.psk_id = ticket_id;
    cfg.psk = NULL;
    CHECK(refused(&cfg));
    cfg.psk = ticket_psk;
    cfg.ticket_binding = NULL;
    CHECK(refused(&cfg));
    // An external PSK: resumption unset, so no ticket and no hostname.
    cfg.ticket_binding = known_binding;
    cfg.resumption = 0;
    CHECK(refused(&cfg));
    // A binding with no ticket beside it.
    cfg = base_cfg();
    cfg.ticket_binding = known_binding;
    CHECK(refused(&cfg));
}

static void test_ticket_names_its_config(void) {
    ch_cfg cfg = base_cfg();
    present(&cfg, ticket_psk, known_binding);
    cfg.hostname = other_host;
    cfg.hostname_len = sizeof other_host;
    CHECK(refused(&cfg));
    cfg = base_cfg();
    present(&cfg, ticket_psk, known_binding);
    cfg.hostname = host_capitals;
    CHECK(resumes(&cfg, ticket_psk));
    // Other anchors: one more, or one whose key differs.
    cfg = base_cfg();
    present(&cfg, ticket_psk, known_binding);
    cfg.anchor_count = 3;
    CHECK(refused(&cfg));
    cfg.anchor_count = 2;
    anchors[1].spki = other_spki;
    anchors[1].spki_len = sizeof other_spki;
    CHECK(refused(&cfg));
    // The binding of another ticket, and a binding one bit off.
    cfg = base_cfg();
    uint8_t other_psk[SHA256_LEN];
    memcpy(other_psk, ticket_psk, SHA256_LEN);
    other_psk[0] ^= 1;
    present(&cfg, other_psk, known_binding);
    CHECK(refused(&cfg));
    uint8_t flipped[SHA256_LEN];
    memcpy(flipped, known_binding, SHA256_LEN);
    flipped[SHA256_LEN - 1] ^= 1;
    present(&cfg, ticket_psk, flipped);
    CHECK(refused(&cfg));
}

static void test_resumed_handshake(void) {
    ch_cfg cfg = base_cfg();
    present(&cfg, ticket_psk, known_binding);
    CHECK(resumes(&cfg, ticket_psk));
    // The resumed hello names the host and offers the ticket, and offers
    // no signature scheme: a server that declines the ticket has no
    // certificate path to take.
    CHECK(hello_first_ext(mock.hello, mock.hello_len) >= 0);
    size_t len = 0;
    const uint8_t *sni = hello_ext(mock.hello, mock.hello_len, EXT_SERVER_NAME, &len);
    CHECK(sni != NULL && len == 5 + sizeof host && memcmp(sni + 5, host, sizeof host) == 0);
    const uint8_t *offer = hello_ext(mock.hello, mock.hello_len, EXT_PRE_SHARED_KEY, &len);
    CHECK(offer != NULL && len > 12 && offer[2] == 0 && offer[3] == 8 &&
          memcmp(offer + 4, ticket_id, 8) == 0);
    uint16_t schemes[8];
    CHECK(hello_sigalgs(mock.hello, mock.hello_len, schemes, 8) == -1);

    // The session's ticket arrives bound to the same hostname and anchors.
    push_ticket(&mock);
    uint8_t got[8];
    CHECK(ch_read(session_tls(), got, sizeof got) == 2 && memcmp(got, "ok", 2) == 0);
    CHECK(received.count == 1 && received.identity_len == 8 &&
          memcmp(received.identity, "ticket-2", 8) == 0);
    uint8_t hash[SHA256_LEN];
    uint8_t binding[SHA256_LEN];
    webpki_ticket_config_hash(&cfg, hash);
    webpki_ticket_binding(received.psk, hash, binding);
    CHECK(memcmp(binding, received.binding, SHA256_LEN) == 0);

    // It resumes the next session under the same name, and no other.
    uint8_t next_psk[SHA256_LEN];
    uint8_t next_binding[SHA256_LEN];
    memcpy(next_psk, received.psk, SHA256_LEN);
    memcpy(next_binding, received.binding, SHA256_LEN);
    cfg = base_cfg();
    present(&cfg, next_psk, next_binding);
    CHECK(resumes(&cfg, next_psk));
    cfg = base_cfg();
    present(&cfg, next_psk, next_binding);
    cfg.hostname = other_host;
    cfg.hostname_len = sizeof other_host;
    CHECK(refused(&cfg));
}

// A server that does not select the ticket fails the handshake closed:
// the hello offered no certificate path.
static void test_server_declines_ticket(void) {
    ch_cfg cfg = base_cfg();
    present(&cfg, ticket_psk, known_binding);
    mock.decline = 1;
    memcpy(mock.psk, ticket_psk, SHA256_LEN);
    CHECK(connect_session(&cfg) == CH_EAUTH);
    CHECK(session_tls()->state == CH_ST_FAILED);
}

#endif
