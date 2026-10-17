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
    cfg.ticket_age_ms = 0x100000005ULL;
    cfg.psk = psk;
    cfg.psk_len = sizeof psk;
    cfg.psk_id = (const uint8_t *)"ticket";
    cfg.psk_id_len = 6;
    CHECK(ch_connect(&t, &cfg) == CH_EIO);
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
