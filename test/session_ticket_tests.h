// The ticket rules ch_connect holds before it sends a byte: the age of a
// presented ticket against its lifetime and the seven days, the shape of
// a kept ticket, and the obfuscated age the hello carries. Included by
// test/session_tests.h after test/session_cfg_tests.h, whose mock I/O it
// uses.
#ifndef CH_TEST_SESSION_TICKET_TESTS_H
#define CH_TEST_SESSION_TICKET_TESTS_H

// The ticket's age against its lifetime, which ch_connect judges before
// it sends a byte (handshake_post.h). RFC 9846 §4.3.11.1 forbids a ticket
// older than its ticket_lifetime (rfc9846.txt:2572-2574), and §4.7.1 one
// kept past 7 days whatever that lifetime says (rfc9846.txt:3259-3261).
// Each pair is the last age accepted and the first refused; an accepted
// config passes the checks and then fails at mock_recv with CH_EIO.
static void test_ticket_age_cfg(void) {
    static uint8_t rxbuf[CH_MIN_RXBUF];
    uint8_t psk[32] = {1};
    mock_io m = {0};
    ch_cfg cfg = {0};
    TEST_CPU_CFG(cfg);
    ch_tls t;
    cfg.buf = rxbuf;
    cfg.buf_len = sizeof rxbuf;
    cfg.send = mock_send;
    cfg.recv = mock_recv;
    cfg.io = &m;
    static ch_saved_ticket saved;
    test_ticket_fill(&saved, psk, sizeof psk, (const uint8_t *)"ticket", 6, 3600);
    // The pin of the last full handshake before the ticket stays in its slot
    // (ticket.h).
    static const uint8_t pin[256] = {0xc1};
    cfg.server_pubkey = pin;
    cfg.server_pubkey_len = sizeof pin;
    test_ticket_trust_pin(&saved, pin, sizeof pin);
    cfg.ticket = &saved;

    // A ticket that arrived this millisecond.
    CHECK(ch_connect(&t, &cfg) == CH_EIO);

    // A lifetime of an hour: 3,600,000 ms is offered, one more is not,
    // and the refusal sends nothing.
    cfg.ticket_age_ms = 3600000U;
    CHECK(ch_connect(&t, &cfg) == CH_EIO);
    int sends_before = m.sends;
    cfg.ticket_age_ms = 3600001U;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
    CHECK(m.sends == sends_before);
    CHECK(t.state == CH_ST_FAILED);

    // A lifetime of 0, which RFC 9846 §4.7.1 says to discard at once, is
    // refused at every age.
    saved.ticket.lifetime_s = 0;
    cfg.ticket_age_ms = 0;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);

    // A lifetime past 7 days, which a server must not send, keeps the
    // 7 days all the same.
    saved.ticket.lifetime_s = CH_TICKET_LIFETIME_MAX + 1;
    cfg.ticket_age_ms = (uint64_t)CH_TICKET_LIFETIME_MAX * 1000U;
    CHECK(ch_connect(&t, &cfg) == CH_EIO);
    cfg.ticket_age_ms += 1;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);

    // An age past 2^32 ms, which reads as 5 ms if anything keeps its low
    // 32 bits alone.
    saved.ticket.lifetime_s = 3600;
    cfg.ticket_age_ms = 0x100000005ULL;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);

    // An identity of 0 bytes, or of more than CH_TICKET_ID_MAX, and a PSK of
    // no hash length are refused before a byte is sent.
    cfg.ticket_age_ms = 0;
    saved.ticket.identity_len = 0;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
    saved.ticket.identity_len = CH_TICKET_ID_MAX + 1;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
    saved.ticket.identity_len = 6;
    saved.ticket.psk_len = 31;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
    saved.ticket.psk_len = sizeof psk;
    CHECK(ch_connect(&t, &cfg) == CH_EIO);

    // An external PSK carries no ticket, so no age is judged.
    cfg.ticket = NULL;
    cfg.server_pubkey = NULL;
    cfg.server_pubkey_len = 0;
    cfg.ticket_age_ms = 0x100000005ULL;
    cfg.psk = psk;
    cfg.psk_len = sizeof psk;
    cfg.psk_id = (const uint8_t *)"ticket";
    cfg.psk_id_len = 6;
    CHECK(ch_connect(&t, &cfg) == CH_EIO);
}

// A kept ticket resumes only under the trust of the last full handshake
// (ticket.h's trust_hash, docs/decisions.md 142). The key in either pin
// slot, or the external PSK, must hash to it. A key in neither slot, or
// another PSK, is refused before a byte is sent, and so is a PSK with the
// bytes of the pin that issued the ticket, because the kind is hashed too.
static void test_ticket_trust_cfg(void) {
    static uint8_t rxbuf[CH_MIN_RXBUF];
    static const uint8_t psk[32] = {1};
    static const uint8_t issuer[256] = {0xc1};
    static const uint8_t other[256] = {0xc3};
    mock_io m = {0};
    ch_cfg cfg = {0};
    TEST_CPU_CFG(cfg);
    ch_tls t;
    cfg.buf = rxbuf;
    cfg.buf_len = sizeof rxbuf;
    cfg.send = mock_send;
    cfg.recv = mock_recv;
    cfg.io = &m;
    static ch_saved_ticket saved;
    test_ticket_fill(&saved, psk, sizeof psk, (const uint8_t *)"ticket", 6, 3600);
    test_ticket_trust_pin(&saved, issuer, sizeof issuer);
    cfg.ticket = &saved;

    cfg.server_pubkey = issuer;
    cfg.server_pubkey_len = sizeof issuer;
    CHECK(ch_connect(&t, &cfg) == CH_EIO);
    cfg.server_pubkey = other;
    cfg.server_pubkey2 = issuer;
    cfg.server_pubkey2_len = sizeof issuer;
    CHECK(ch_connect(&t, &cfg) == CH_EIO);
    int sends_before = m.sends;
    cfg.server_pubkey2 = other;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL && m.sends == sends_before);
    cfg.server_pubkey2 = NULL;
    cfg.server_pubkey2_len = 0;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL && m.sends == sends_before);

    // The external PSK as the trust.
    static const uint8_t external[32] = {9};
    cfg.server_pubkey = NULL;
    cfg.server_pubkey_len = 0;
    cfg.psk = external;
    cfg.psk_len = sizeof external;
    cfg.psk_id = (const uint8_t *)"device";
    cfg.psk_id_len = 6;
    test_ticket_trust_psk(&saved, external, sizeof external);
    CHECK(ch_connect(&t, &cfg) == CH_EIO);
    test_ticket_trust_psk(&saved, psk, sizeof psk);
    int sends_after_psk = m.sends;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL && m.sends == sends_after_psk);
    test_ticket_trust_pin(&saved, external, sizeof external);
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL && m.sends == sends_after_psk);
}

// The trust_hash of a ticket this session receives, after a handshake
// that the key in pin slot slot authenticated (ch_tls.pin_slot).
static void trust_after_slot(uint8_t slot, const uint8_t *key_a, const uint8_t *key_b,
                             size_t key_len, uint8_t out[SHA256_LEN]) {
    uint8_t secret[SHA256_LEN];
    ch_rand_bytes(secret, sizeof secret);
    rec_dir server;
    TEST_CPU_DIR(server);
    rec_dir_init(&server, secret);
    mock_io m = {0};
    static uint8_t rxbuf[1024];
    ch_tls t;
    mock_session(&t, &m, rxbuf, sizeof rxbuf, secret, NULL);
    t.cfg.server_pubkey = key_a;
    t.cfg.server_pubkey_len = key_len;
    t.cfg.server_pubkey2 = key_b;
    t.cfg.server_pubkey2_len = key_len;
    t.pin_slot = slot;
    uint8_t msg[96];
    const uint8_t empty_exts[2] = {0, 0};
    size_t msg_len = build_ticket_msg(msg, sizeof msg, 3600, 2, empty_exts, sizeof empty_exts);
    mock_push(&m, &server, REC_HANDSHAKE, msg, msg_len);
    mock_push(&m, &server, REC_APPDATA, (const uint8_t *)"hola", 4);
    uint8_t got[16];
    CHECK(ch_read(&t, got, sizeof got) == 4 && m.tickets == 1);
    memcpy(out, m.trust_hash, SHA256_LEN);
}

// A ticket names the key in the pin slot that authenticated its
// handshake. So a ticket from a handshake that the key in slot B
// authenticated still resumes after step 3 of a rotation moves that key
// to slot A (docs/rotation.md).
static void test_ticket_trust_slot(void) {
    static const uint8_t current[256] = {0xc1};
    static const uint8_t staged[256] = {0xc3};
    uint8_t got[SHA256_LEN];
    uint8_t want[SHA256_LEN];
    trust_after_slot(1, current, staged, sizeof current, got);
    hspost_trust_hash(HSPOST_TRUST_PIN, current, sizeof current, want);
    CHECK(memcmp(got, want, SHA256_LEN) == 0);
    trust_after_slot(2, current, staged, sizeof current, got);
    hspost_trust_hash(HSPOST_TRUST_PIN, staged, sizeof staged, want);
    CHECK(memcmp(got, want, SHA256_LEN) == 0);
}

// ch_ticket_obfuscated_age: the age plus ticket_age_add, modulo 2^32 (RFC
// 9846 §4.3.11.1, rfc9846.txt:2574-2578). The ticket is one kept after
// on_ticket returned, with every field but age_add unset.
static void test_ticket_obfuscated_age(void) {
    ch_ticket ticket;
    memset(&ticket, 0, sizeof ticket);
    ticket.age_add = 7;
    CHECK(ch_ticket_obfuscated_age(&ticket, 5000) == 5007U);
    // The sum wraps: 0xfffffff0 + 0x20 is 0x10 modulo 2^32.
    ticket.age_add = 0xfffffff0U;
    CHECK(ch_ticket_obfuscated_age(&ticket, 0x0f) == 0xffffffffU);
    CHECK(ch_ticket_obfuscated_age(&ticket, 0x10) == 0U);
    CHECK(ch_ticket_obfuscated_age(&ticket, 0x20) == 0x10U);
    // An age past 2^32 ms contributes its low 32 bits.
    CHECK(ch_ticket_obfuscated_age(&ticket, 0x100000020ULL) == 0x10U);
    CHECK(ch_ticket_obfuscated_age(&ticket, UINT64_MAX) == 0xffffffefU);
}

#endif
