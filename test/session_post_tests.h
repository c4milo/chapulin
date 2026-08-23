// Session behavior over the mock transport: post-handshake messages
// (fragmented NewSessionTicket, KeyUpdate, alerts, close), the ch_write
// chunk loop, the receive-side padding strip, and the sequence-number
// boundary. Included by session_tests.h after the mock helpers exist;
// not a standalone translation unit.
#ifndef CH_SESSION_POST_TESTS_H
#define CH_SESSION_POST_TESTS_H

// Post-handshake behavior the e2e cannot reach: a NewSessionTicket
// fragmented across records (RFC 9846 §5.1), a KeyUpdate that rekeys both
// directions, then application data under the updated key.
static void test_post_handshake(void) {
    uint8_t secret[SHA256_LEN];
    ch_rand_bytes(secret, sizeof secret);
    rec_dir server;
    rec_dir_init(&server, secret);
    mock_io m = {0};
    static uint8_t rxbuf[1024];
    ch_tls t;
    mock_session(&t, &m, rxbuf, sizeof rxbuf, secret, NULL);

    // NST: lifetime, age_add, nonce(2), identity(90), no extensions.
    uint8_t ticket_msg[4 + 105];
    wbuf w;
    wb_init(&w, ticket_msg, sizeof ticket_msg);
    wb_u8(&w, 4); // HS_NEW_SESSION_TICKET
    size_t msg = wb_mark(&w, 3);
    wb_u16(&w, 0);
    wb_u16(&w, 3600); // lifetime
    wb_u16(&w, 0);
    wb_u16(&w, 7); // age_add
    wb_u8(&w, 2);
    wb_u16(&w, 0x0102); // nonce
    wb_u16(&w, 90);
    for (int i = 0; i < 90; i++) {
        wb_u8(&w, (uint8_t)i);
    }
    wb_u16(&w, 0); // extensions
    wb_patch24(&w, msg);
    CHECK(!w.err);

    // Fragment it: 10 bytes, then the rest (splits the ticket body).
    mock_push(&m, &server, REC_HANDSHAKE, ticket_msg, 10);
    mock_push(&m, &server, REC_HANDSHAKE, ticket_msg + 10, w.len - 10);
    // KeyUpdate with update_requested, then data under the updated key.
    const uint8_t key_update[5] = {24, 0, 0, 1, 1};
    mock_push(&m, &server, REC_HANDSHAKE, key_update, sizeof key_update);
    uint8_t s2[SHA256_LEN];
    memcpy(s2, secret, sizeof s2);
    rec_dir_update(s2, &server);
    mock_push(&m, &server, REC_APPDATA, (const uint8_t *)"hola", 4);

    uint8_t out[16];
    int got = ch_read(&t, out, sizeof out);
    CHECK(got == 4 && memcmp(out, "hola", 4) == 0);
    CHECK(m.tickets == 1);
    CHECK(m.sent > 0); // the KeyUpdate reply went out
    CHECK(t.state == CH_ST_CONNECTED);

    // Zero-length reads are a caller bug, never the close sentinel.
    CHECK(ch_read(&t, out, 0) == CH_EINVAL);

    // Clean close: exactly one close_notify reply, then 0 forever and no
    // record sealed under wiped keys on a second close.
    const uint8_t close_notify[2] = {1, 0};
    mock_push(&m, &server, REC_ALERT, close_notify, 2);
    size_t before_close = m.sent;
    CHECK(ch_read(&t, out, sizeof out) == 0);
    CHECK(m.sent > before_close); // our close_notify, under live keys
    size_t after_close = m.sent;
    ch_close(&t);
    CHECK(m.sent == after_close); // keys wiped: nothing more on the wire
    CHECK(ch_read(&t, out, sizeof out) == 0);
}

// The ch_write chunk loop over the mock transport: the exact-limit and
// limit-plus-one boundaries against a server-side reader, then an I/O
// failure mid-loop, which must kill the session with no partial record
// state surviving.
static void test_ch_write(void) {
    uint8_t secret[SHA256_LEN];
    ch_rand_bytes(secret, sizeof secret);
    mock_io m = {0};
    static uint8_t rxbuf[1024];
    ch_tls t;
    uint8_t wr_secret[SHA256_LEN];
    mock_session(&t, &m, rxbuf, sizeof rxbuf, secret, wr_secret);
    t.peer_limit = 64; // a small limit makes the boundary cheap to cross

    rec_dir reader;
    rec_dir_init(&reader, wr_secret);
    uint8_t msg[65];
    for (size_t i = 0; i < sizeof msg; i++) {
        msg[i] = (uint8_t)i;
    }
    uint8_t pt[512];
    size_t pt_len = 0;
    uint8_t type = 0;

    // Exactly peer_limit: one record, no remainder record after it.
    CHECK(ch_write(&t, msg, 64) == CH_OK);
    CHECK(m.sends == 1);
    size_t at = mock_pop_client_record(&m, 0, &reader, pt, sizeof pt, &pt_len, &type);
    CHECK(type == REC_APPDATA && pt_len == 64 && memcmp(pt, msg, 64) == 0);
    CHECK(at == m.tx_len);

    // peer_limit + 1: exactly two records, 64 bytes then 1.
    CHECK(ch_write(&t, msg, 65) == CH_OK);
    CHECK(m.sends == 3);
    at = mock_pop_client_record(&m, at, &reader, pt, sizeof pt, &pt_len, &type);
    CHECK(type == REC_APPDATA && pt_len == 64 && memcmp(pt, msg, 64) == 0);
    at = mock_pop_client_record(&m, at, &reader, pt, sizeof pt, &pt_len, &type);
    CHECK(type == REC_APPDATA && pt_len == 1 && pt[0] == msg[64]);
    CHECK(at == m.tx_len);

    // An EIO between chunks: the first record goes out, the second send
    // fails. The session dies — keys wiped, no further bytes ever leave.
    mock_io m2 = {0};
    m2.fail_after = 2;
    ch_tls t2;
    mock_session(&t2, &m2, rxbuf, sizeof rxbuf, secret, NULL);
    t2.peer_limit = 64;
    CHECK(ch_write(&t2, msg, 65) == CH_EIO);
    CHECK(t2.state == CH_ST_FAILED && t2.keys == 0);
    CHECK(ch_write(&t2, msg, 1) == CH_EPROTO); // dead sessions refuse writes
    // Count attempts, not bytes: the armed failure knob keeps sent from
    // growing even if close wrongly transmitted, so bytes cannot fail.
    int sends_after_fail = m2.sends;
    ch_close(&t2);
    CHECK(m2.sends == sends_after_fail); // wiped keys: close attempts nothing
}

// The receive-side padding strip (RFC 9846 §5.4): chapulin never sends
// padding and neither do the e2e peers, so this path runs nowhere else.
// Seal an inner plaintext with trailing zeros after the content type by
// hand and check the content and type come back right.
static void test_record_padding(void) {
    uint8_t secret[SHA256_LEN];
    ch_rand_bytes(secret, sizeof secret);
    rec_dir server;
    rec_dir_init(&server, secret);
    rec_dir client;
    rec_dir_init(&client, secret);

    // inner = "pad" + type(APPDATA) + 5 zeros of padding.
    uint8_t inner[9] = {'p', 'a', 'd', REC_APPDATA, 0, 0, 0, 0, 0};
    uint8_t rec[REC_HDR + sizeof inner + AEAD_TAG];
    rec[0] = REC_APPDATA; // outer type is always application_data
    rec[1] = 0x03;
    rec[2] = 0x03;
    rec[3] = 0;
    rec[4] = sizeof inner + AEAD_TAG;
    uint8_t nonce[AEAD_NONCE];
    for (size_t i = 0; i < AEAD_NONCE; i++) {
        nonce[i] = server.iv[i]; // seq 0: nonce is the static IV
    }
    aead_seal(server.key, nonce, rec, REC_HDR, inner, sizeof inner, rec + REC_HDR,
              rec + REC_HDR + sizeof inner);
    server.seq++;

    uint8_t pt[32];
    size_t pt_len = 0;
    uint8_t type = 0;
    CHECK(rec_open(&client, rec, sizeof rec, pt, sizeof pt, &pt_len, &type) == 0);
    CHECK(type == REC_APPDATA && pt_len == 3 && memcmp(pt, "pad", 3) == 0);

    // All-padding record (no content type at all) must be rejected.
    uint8_t empty[4] = {0, 0, 0, 0};
    rec[4] = sizeof empty + AEAD_TAG;
    for (size_t i = 0; i < AEAD_NONCE; i++) {
        nonce[i] = server.iv[i] ^ (i == AEAD_NONCE - 1 ? 1 : 0); // seq 1
    }
    aead_seal(server.key, nonce, rec, REC_HDR, empty, sizeof empty, rec + REC_HDR,
              rec + REC_HDR + sizeof empty);
    client.seq = 1;
    CHECK(rec_open(&client, rec, REC_HDR + sizeof empty + AEAD_TAG, pt, sizeof pt, &pt_len,
                   &type) == -1);
}

// A spent sequence space refuses to protect or accept further records
// instead of wrapping into (key, nonce) reuse. The boundary is exact: the
// last representable sequence still works; UINT64_MAX refuses.
static void test_seq_exhaustion(void) {
    uint8_t secret[SHA256_LEN];
    ch_rand_bytes(secret, sizeof secret);
    uint8_t rec[64];
    uint8_t pt[8] = {0};
    size_t n = 0;
    uint8_t type = 0;

    // The last representable sequence still protects a record.
    rec_dir d;
    rec_dir_init(&d, secret);
    d.seq = UINT64_MAX - 1;
    CHECK(rec_seal(&d, REC_APPDATA, pt, sizeof pt, rec, sizeof rec, &n) == 0);

    // One past it, both directions refuse before the increment could wrap.
    rec_dir e;
    rec_dir_init(&e, secret);
    e.seq = UINT64_MAX;
    CHECK(rec_seal(&e, REC_APPDATA, pt, sizeof pt, rec, sizeof rec, &n) == -1);
    CHECK(rec_open(&e, rec, sizeof rec, rec, sizeof rec, &n, &type) == -1);
}

// RFC 9846 conformance the e2e cannot steer: a user_canceled alert is
// read through until close_notify arrives, and a sender at the KeyUpdate
// epoch cap ignores update_requested instead of replying.
static void test_alerts_and_epochs(void) {
    uint8_t secret[SHA256_LEN];
    ch_rand_bytes(secret, sizeof secret);
    rec_dir server;
    rec_dir_init(&server, secret);
    mock_io m = {0};
    static uint8_t rxbuf[1024];
    ch_tls t;
    mock_session(&t, &m, rxbuf, sizeof rxbuf, secret, NULL);

    // user_canceled, then close_notify: a clean close, not an error.
    const uint8_t user_canceled[2] = {1, 90};
    const uint8_t close_notify[2] = {1, 0};
    mock_push(&m, &server, REC_ALERT, user_canceled, 2);
    mock_push(&m, &server, REC_ALERT, close_notify, 2);
    uint8_t out[16];
    CHECK(ch_read(&t, out, sizeof out) == 0);

    // At the epoch cap: the receive keys still update (we can read data
    // under the peer's new key) but no reply KeyUpdate goes out.
    mock_io m2 = {0};
    ch_tls t2;
    mock_session(&t2, &m2, rxbuf, sizeof rxbuf, secret, NULL);
    t2.send_epochs = 0xffffffffffffULL;
    rec_dir server2;
    rec_dir_init(&server2, secret);
    const uint8_t key_update[5] = {24, 0, 0, 1, 1};
    mock_push(&m2, &server2, REC_HANDSHAKE, key_update, sizeof key_update);
    uint8_t s2[SHA256_LEN];
    memcpy(s2, secret, sizeof s2);
    rec_dir_update(s2, &server2);
    mock_push(&m2, &server2, REC_APPDATA, (const uint8_t *)"hola", 4);
    size_t sent_before = m2.sent;
    int got = ch_read(&t2, out, sizeof out);
    CHECK(got == 4 && memcmp(out, "hola", 4) == 0);
    CHECK(m2.sent == sent_before); // no reply at the cap
}

#endif
