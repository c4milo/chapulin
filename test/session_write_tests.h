// What the connected session sends, sized in advance: ch_writable_len
// against the ch_write that sends what it counts, and the records ch_read
// sends in answer to KeyUpdates (tls.h). Included by session_tests.h after
// the mock helpers exist; not a standalone translation unit.
#ifndef CH_SESSION_WRITE_TESTS_H
#define CH_SESSION_WRITE_TESTS_H

// What one ch_read sends in answer to KeyUpdates: CH_KEY_UPDATE_RECORD_LEN
// bytes for each one whose sender asked for an answer, so one record that
// carries two such messages gets two records back (tls.h). A caller that
// sizes the bytes ch_read may send sizes them for that.
static void test_key_update_replies(void) {
    uint8_t secret[SHA256_LEN];
    ch_rand_bytes(secret, sizeof secret);
    rec_dir server;
    rec_dir_init(&server, secret);
    mock_io m = {0};
    static uint8_t rxbuf[1024];
    ch_tls t;
    mock_session(&t, &m, rxbuf, sizeof rxbuf, secret, NULL);
    const uint8_t two_updates[10] = {24, 0, 0, 1, 1, 24, 0, 0, 1, 1};
    mock_push(&m, &server, REC_HANDSHAKE, two_updates, sizeof two_updates);
    // The client's read key moved twice; the data after follows it.
    uint8_t next[SHA256_LEN];
    memcpy(next, secret, sizeof next);
    rec_dir_update(next, &server);
    rec_dir_update(next, &server);
    mock_push(&m, &server, REC_APPDATA, (const uint8_t *)"hola", 4);
    uint8_t out[16];
    CHECK(ch_read(&t, out, sizeof out) == 4);
    CHECK(m.sends == 2 && m.sent == 2 * (size_t)CH_KEY_UPDATE_RECORD_LEN);
}

// The bytes one ch_write of n bytes hands the session's mock_send, read
// through the session's own cfg.io.
static size_t sent_by_write(ch_tls *t, const uint8_t *p, size_t n) {
    const mock_io *m = t->cfg.io;
    size_t before = m->sent;
    CHECK(ch_write(t, p, n) == CH_OK);
    return m->sent - before;
}

// ch_writable_len against the ch_write that sends what it counts (tls.h).
// For each record limit and every cap up to three whole records and one
// byte, the answer's records fit cap and one byte more does not. The
// limits are 63, the least a peer's record_size_limit of 64 leaves; 200,
// a limit between; and CH_TX_PT itself. mock_send counts every byte it is
// handed in m.sent.
static void test_writable_len(void) {
    uint8_t secret[SHA256_LEN];
    ch_rand_bytes(secret, sizeof secret);
    static uint8_t rxbuf[1024];
    static const uint8_t msg[3 * (CH_TX_PT + REC_OVERHEAD) + 2] = {0};
    const uint16_t limits[3] = {63, 200, CH_TX_PT};
    for (size_t i = 0; i < sizeof limits / sizeof limits[0]; i++) {
        mock_io m = {0};
        ch_tls t;
        mock_session(&t, &m, rxbuf, sizeof rxbuf, secret, NULL);
        t.peer_limit = limits[i];
        size_t record_max = (size_t)limits[i] + REC_OVERHEAD;
        for (size_t cap = 0; cap <= 3 * record_max + 1; cap++) {
            size_t n = ch_writable_len(&t, cap);
            CHECK(sent_by_write(&t, msg, n) <= cap);
            CHECK(sent_by_write(&t, msg, n + 1) > cap);
        }
    }

    // The rows tls.h states, at the build's own limit.
    mock_io m = {0};
    ch_tls t;
    mock_session(&t, &m, rxbuf, sizeof rxbuf, secret, NULL);
    t.peer_limit = CH_TX_PT;
    CHECK(ch_writable_len(&t, REC_OVERHEAD) == 0);     // a record with no byte
    CHECK(ch_writable_len(&t, REC_OVERHEAD + 1) == 1); // a record of one byte
    CHECK(ch_writable_len(&t, CH_TX_PT + REC_OVERHEAD) == CH_TX_PT);
    CHECK(ch_writable_len(&t, CH_TX_PT + 2 * REC_OVERHEAD) == CH_TX_PT);
    CHECK(ch_writable_len(&t, CH_TX_PT + 2 * REC_OVERHEAD + 1) == CH_TX_PT + 1);
    // A peer limit above CH_TX_PT still leaves CH_TX_PT, as in ch_write.
    t.peer_limit = CH_TX_PT + 100;
    CHECK(ch_writable_len(&t, CH_TX_PT + 2 * REC_OVERHEAD + 1) == CH_TX_PT + 1);
    // The largest cap there is: whole records all the way.
    size_t whole = SIZE_MAX / (CH_TX_PT + REC_OVERHEAD);
    size_t rest = SIZE_MAX - whole * (CH_TX_PT + REC_OVERHEAD);
    CHECK(ch_writable_len(&t, SIZE_MAX) ==
          whole * CH_TX_PT + (rest > REC_OVERHEAD ? rest - REC_OVERHEAD : 0));
    // A session with no limit, as a zeroed one has: nothing.
    t.peer_limit = 0;
    CHECK(ch_writable_len(&t, 4096) == 0);
}

#endif
