// What the connected session sends, sized in advance: ch_writable_len
// against the ch_write that sends what it counts, the KeyUpdate a peer's
// request owes among it (tls.h). Included by session_tests.h after the
// mock helpers exist; not a standalone translation unit.
#ifndef CH_SESSION_WRITE_TESTS_H
#define CH_SESSION_WRITE_TESTS_H

// request_update has two values (RFC 9846 §4.7.3), and any other ends the
// connection with illegal_parameter (rfc9846.txt:3362-3365). 1 is the last
// value read as a request, 2 the first refused, and 255 the last byte
// there is. The read of an accepted one sends nothing, and a request owes
// one answer. A refused KeyUpdate owes no answer and sends that alert alone,
// under the write key the session had.
static void read_key_update_request(uint8_t request) {
    uint8_t secret[SHA256_LEN];
    ch_rand_bytes(secret, sizeof secret);
    rec_dir server;
    TEST_CPU_DIR(server);
    rec_dir_init(&server, secret);
    mock_io m = {0};
    static uint8_t rxbuf[1024];
    ch_tls t;
    uint8_t wr_secret[SHA256_LEN];
    mock_session(&t, &m, rxbuf, sizeof rxbuf, secret, wr_secret);
    rec_dir reader;
    TEST_CPU_DIR(reader);
    rec_dir_init(&reader, wr_secret);
    const uint8_t key_update[5] = {HS_KEY_UPDATE, 0, 0, 1, request};
    mock_push(&m, &server, REC_HANDSHAKE, key_update, sizeof key_update);
    uint8_t out[16];
    if (request <= 1) {
        rec_dir_update(secret, &server);
        mock_push(&m, &server, REC_APPDATA, (const uint8_t *)"hola", 4);
        CHECK(ch_read(&t, out, sizeof out) == 4);
        CHECK(ch_alert_sent(&t) == 0 && m.sends == 0 && t.key_update_owed == request);
        return;
    }
    CHECK(ch_read(&t, out, sizeof out) == CH_EPROTO);
    CHECK(ch_alert_sent(&t) == ALERT_ILLEGAL_PARAMETER);
    uint8_t pt[16];
    size_t pt_len = 0;
    uint8_t type = 0;
    size_t at = mock_pop_client_record(&m, 0, &reader, pt, sizeof pt, &pt_len, &type);
    CHECK(type == REC_ALERT && pt_len == 2 && pt[0] == 2 && pt[1] == ALERT_ILLEGAL_PARAMETER);
    CHECK(at == m.tx_len && m.sends == 1);
}

// A KeyUpdate's body is the one request_update byte, and a body of any
// other length does not parse, which RFC 9846 §6 answers with
// decode_error (rfc9846.txt:3785-3788). One byte is
// the length read_key_update_request reads; 0 and 2 are the lengths on
// either side, each refused before any rekey with that alert alone.
static void read_key_update_body(size_t body_len) {
    uint8_t secret[SHA256_LEN];
    ch_rand_bytes(secret, sizeof secret);
    rec_dir server;
    TEST_CPU_DIR(server);
    rec_dir_init(&server, secret);
    mock_io m = {0};
    static uint8_t rxbuf[1024];
    ch_tls t;
    uint8_t wr_secret[SHA256_LEN];
    mock_session(&t, &m, rxbuf, sizeof rxbuf, secret, wr_secret);
    rec_dir reader;
    TEST_CPU_DIR(reader);
    rec_dir_init(&reader, wr_secret);
    const uint8_t key_update[6] = {HS_KEY_UPDATE, 0, 0, (uint8_t)body_len, 1, 0};
    mock_push(&m, &server, REC_HANDSHAKE, key_update, 4 + body_len);
    uint8_t out[16];
    CHECK(ch_read(&t, out, sizeof out) == CH_EPROTO);
    CHECK(ch_alert_sent(&t) == ALERT_DECODE_ERROR);
    uint8_t pt[16];
    size_t pt_len = 0;
    uint8_t type = 0;
    size_t at = mock_pop_client_record(&m, 0, &reader, pt, sizeof pt, &pt_len, &type);
    CHECK(type == REC_ALERT && pt_len == 2 && pt[0] == 2 && pt[1] == ALERT_DECODE_ERROR);
    CHECK(at == m.tx_len && m.sends == 1);
}

static void test_key_update_request(void) {
    read_key_update_request(0);
    read_key_update_request(1);
    read_key_update_request(2);
    read_key_update_request(255);
    read_key_update_body(0);
    read_key_update_body(2);
}

// The bytes one ch_write of n bytes hands the session's mock_send, read
// through the session's own cfg.io.
static size_t sent_by_write(ch_tls *t, const uint8_t *p, size_t n) {
    const mock_io *m = t->cfg.io;
    size_t before = m->sent;
    CHECK(ch_write(t, p, n) == CH_OK);
    return m->sent - before;
}

// The same while the peer's request is owed an answer: a write of a byte
// or more sends the KeyUpdate record first, and a write of none sends
// nothing and still owes it.
static size_t sent_by_write_owed(ch_tls *t, const uint8_t *p, size_t n) {
    t->key_update_owed = 1;
    size_t sent = sent_by_write(t, p, n);
    CHECK(t->key_update_owed == (n == 0));
    return sent;
}

// ch_writable_len against the ch_write that sends what it counts (tls.h).
// For each record limit and every cap up to three whole records, a
// KeyUpdate record and one byte, the records of what it returns fit cap
// and one byte more does not, with no answer owed and with one owed. The
// limits are 63, the least a peer's record_size_limit of 64 leaves; 200, a
// limit between; and CH_TX_PT itself. mock_send counts every byte it is
// handed in m.sent.
static void test_writable_len(void) {
    uint8_t secret[SHA256_LEN];
    ch_rand_bytes(secret, sizeof secret);
    static uint8_t rxbuf[1024];
    static const uint8_t msg[3 * (CH_TX_PT + REC_OVERHEAD) + CH_KEY_UPDATE_RECORD_LEN + 2] = {0};
    const uint16_t limits[3] = {63, 200, CH_TX_PT};
    for (size_t i = 0; i < sizeof limits / sizeof limits[0]; i++) {
        mock_io m = {0};
        ch_tls t;
        mock_session(&t, &m, rxbuf, sizeof rxbuf, secret, NULL);
        t.peer_limit = limits[i];
        size_t record_max = (size_t)limits[i] + REC_OVERHEAD;
        for (size_t cap = 0; cap <= 3 * record_max + CH_KEY_UPDATE_RECORD_LEN + 1; cap++) {
            size_t n = ch_writable_len(&t, cap);
            CHECK(sent_by_write(&t, msg, n) <= cap);
            CHECK(sent_by_write(&t, msg, n + 1) > cap);
            t.key_update_owed = 1;
            n = ch_writable_len(&t, cap);
            CHECK(sent_by_write_owed(&t, msg, n) <= cap);
            CHECK(sent_by_write_owed(&t, msg, n + 1) > cap);
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
    // An answer owed: its KeyUpdate record comes first, then the rows above
    // shifted by its 27 bytes, and at SIZE_MAX whole records after it.
    t.peer_limit = CH_TX_PT;
    t.key_update_owed = 1;
    size_t key_update = CH_KEY_UPDATE_RECORD_LEN;
    CHECK(ch_writable_len(&t, 0) == 0);
    CHECK(ch_writable_len(&t, key_update + REC_OVERHEAD) == 0);
    CHECK(ch_writable_len(&t, key_update + REC_OVERHEAD + 1) == 1);
    CHECK(ch_writable_len(&t, key_update + CH_TX_PT + 2 * (size_t)REC_OVERHEAD) == CH_TX_PT);
    CHECK(ch_writable_len(&t, key_update + CH_TX_PT + 2 * (size_t)REC_OVERHEAD + 1) ==
          CH_TX_PT + 1);
    whole = (SIZE_MAX - key_update) / (CH_TX_PT + REC_OVERHEAD);
    rest = SIZE_MAX - key_update - whole * (CH_TX_PT + REC_OVERHEAD);
    CHECK(ch_writable_len(&t, SIZE_MAX) ==
          whole * CH_TX_PT + (rest > REC_OVERHEAD ? rest - REC_OVERHEAD : 0));
    t.key_update_owed = 0;
    // A session with no limit, as a zeroed one has: nothing.
    t.peer_limit = 0;
    CHECK(ch_writable_len(&t, 4096) == 0);
}

// The wire bytes one write sends from a copy of start: ch_write over all
// of msg when part_count is 0, ch_write_parts over the parts otherwise.
// Each run starts from the same keys and sequence numbers, so two runs
// that seal the same records send the same bytes.
static size_t wire_of_write(const ch_tls *start, mock_io *m, const uint8_t *msg, size_t n,
                            const ch_part *parts, size_t part_count, uint8_t *wire, size_t cap) {
    static ch_tls t;
    t = *start;
    memset(m, 0, sizeof *m);
    t.cfg.io = m;
    if (part_count == 0) {
        CHECK(ch_write(&t, msg, n) == CH_OK);
    } else {
        CHECK(ch_write_parts(&t, parts, part_count) == CH_OK);
    }
    CHECK(m->tx_len <= cap);
    memcpy(wire, m->tx, m->tx_len);
    return m->tx_len;
}

// ch_write_parts sends the records ch_write sends for the parts joined in
// one buffer (tls.h). At a record limit of 63, each split below seals the
// same bytes as ch_write over the whole message: a 9-byte header and a
// payload, as an h2 DATA frame is; a part that ends on the record limit
// and one that ends a byte before it; a part longer than a record; parts
// of 0 bytes, one with no pointer, before, between and after; and one
// part. Every byte of the message differs from its neighbours, so a byte
// copied from the wrong place changes the wire. Each runs with no answer
// owed and with one owed, which puts a KeyUpdate record first.
static void test_write_parts(void) {
    uint8_t secret[SHA256_LEN];
    ch_rand_bytes(secret, sizeof secret);
    static uint8_t rxbuf[1024];
    static uint8_t msg[200];
    for (size_t i = 0; i < sizeof msg; i++) {
        msg[i] = (uint8_t)(i * 7 + 3);
    }
    static const size_t splits[][5] = {
        {9,   191, 0,  0,   0},
        {63,  137, 0,  0,   0},
        {62,  1,   64, 73,  0},
        {100, 100, 0,  0,   0},
        {0,   9,   0,  191, 0},
        {200, 0,   0,  0,   0},
    };
    static mock_io m;
    static ch_tls start;
    static uint8_t want[2048];
    static uint8_t got[2048];
    for (int owed = 0; owed <= 1; owed++) {
        mock_session(&start, &m, rxbuf, sizeof rxbuf, secret, NULL);
        start.peer_limit = 63;
        start.key_update_owed = (uint8_t)owed;
        size_t want_len = wire_of_write(&start, &m, msg, sizeof msg, NULL, 0, want, sizeof want);
        // Three records of 63 bytes and one of 11.
        CHECK(want_len == 3 * (63 + REC_OVERHEAD) + 11 + REC_OVERHEAD +
                              (size_t)owed * CH_KEY_UPDATE_RECORD_LEN);
        for (size_t s = 0; s < sizeof splits / sizeof splits[0]; s++) {
            ch_part parts[5];
            size_t at = 0;
            for (size_t i = 0; i < 5; i++) {
                parts[i].pt = splits[s][i] == 0 && i % 2 == 0 ? NULL : msg + at;
                parts[i].pt_len = splits[s][i];
                at += splits[s][i];
            }
            CHECK(at == sizeof msg);
            size_t got_len = wire_of_write(&start, &m, NULL, 0, parts, 5, got, sizeof got);
            CHECK(got_len == want_len && memcmp(got, want, want_len) == 0);
        }
        // Parts that hold no byte send nothing, not even an owed answer.
        const ch_part empty[2] = {
            {NULL, 0},
            {msg,  0}
        };
        CHECK(wire_of_write(&start, &m, NULL, 0, empty, 2, got, sizeof got) == 0);
        CHECK(m.sends == 0);
    }
    // No parts at all, and a session that is not connected, which sends
    // nothing and returns CH_EPROTO as ch_write does.
    mock_session(&start, &m, rxbuf, sizeof rxbuf, secret, NULL);
    CHECK(ch_write_parts(&start, NULL, 0) == CH_OK && m.sends == 0);
    start.state = CH_ST_FAILED;
    const ch_part one = {msg, 1};
    CHECK(ch_write_parts(&start, &one, 1) == CH_EPROTO && m.sends == 0);
}

#endif
