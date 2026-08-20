// Session-level tests over a mock transport: the paths e2e cannot steer
// (fragmented post-handshake messages, KeyUpdate both ways, close
// semantics) and ch_connect's config validation. Included by test/unit.c
// only, after its CHECK macro and includes.
#ifndef CH_SESSION_TESTS_H
#define CH_SESSION_TESTS_H

// Mock transport: the "server" is a byte queue we stuff records into.
// The send side captures the client's bytes so tests can decrypt them
// with the server's copy of the client write key, and fail_after makes
// the Nth send call return an I/O error (0 = never fail).
typedef struct {
    uint8_t data[4096];
    size_t len;
    size_t off;
    int tickets;
    size_t sent;      // bytes the client transmitted (KeyUpdate replies etc.)
    uint8_t tx[4096]; // capture of everything the client sent
    size_t tx_len;
    int sends;      // send calls so far
    int fail_after; // fail the send when sends reaches this count
} mock_io;

static int mock_send(void *io, const uint8_t *p, size_t n) {
    mock_io *m = io;
    m->sends++;
    if (m->fail_after != 0 && m->sends >= m->fail_after) {
        return -1;
    }
    if (m->tx_len + n <= sizeof m->tx) {
        memcpy(m->tx + m->tx_len, p, n);
        m->tx_len += n;
    }
    m->sent += n;
    return 0;
}

static int mock_recv(void *io, uint8_t *p, size_t n) {
    mock_io *m = io;
    size_t left = m->len - m->off;
    if (left == 0) {
        return -1;
    }
    size_t take = n < left ? n : left;
    memcpy(p, m->data + m->off, take);
    m->off += take;
    return (int)take;
}

static void mock_on_ticket(void *io, const ch_ticket *ticket) {
    (void)ticket;
    ((mock_io *)io)->tickets++;
}

// Builds a connected session whose read keys mirror server, fed by m.
static void mock_session(ch_tls *t, mock_io *m, uint8_t *rxbuf, size_t rxlen,
                         const uint8_t secret[SHA256_LEN], uint8_t wr_secret_out[SHA256_LEN]) {
    memset(t, 0, sizeof *t);
    t->cfg.buf = rxbuf;
    t->cfg.buf_len = rxlen;
    t->cfg.send = mock_send;
    t->cfg.recv = mock_recv;
    t->cfg.io = m;
    t->cfg.on_ticket = mock_on_ticket;
    memcpy(t->rd_secret, secret, SHA256_LEN);
    rec_dir_init(&t->rd, t->rd_secret);
    uint8_t write_secret[SHA256_LEN];
    ch_rand_bytes(write_secret, sizeof write_secret);
    if (wr_secret_out != NULL) {
        memcpy(wr_secret_out, write_secret, SHA256_LEN);
    }
    memcpy(t->wr_secret, write_secret, SHA256_LEN);
    rec_dir_init(&t->wr, t->wr_secret);
    t->state = CH_ST_CONNECTED;
    t->keys = 1;
    t->peer_limit = CH_TX_PT;
}

static void mock_push(mock_io *m, rec_dir *server, uint8_t type, const uint8_t *pt, size_t n) {
    size_t record_len = 0;
    CHECK(rec_seal(server, type, pt, n, m->data + m->len, sizeof m->data - m->len, &record_len) ==
          0);
    m->len += record_len;
}

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

// Pops one record off the client's captured transmit bytes and opens it
// with the server's copy of the client write key.
static size_t mock_pop_client_record(mock_io *m, size_t at, rec_dir *reader, uint8_t *pt,
                                     size_t cap, size_t *pt_len, uint8_t *type) {
    CHECK(m->tx_len >= at + REC_HDR);
    size_t body = ((size_t)m->tx[at + 3] << 8) | m->tx[at + 4];
    CHECK(m->tx_len >= at + REC_HDR + body);
    CHECK(rec_open(reader, m->tx + at, REC_HDR + body, pt, cap, pt_len, type) == 0);
    return at + REC_HDR + body;
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

// ECDSA P-256/SHA-256 verify. Key and the "sample"/"test" signatures are
// RFC 6979 A.2.5; the third signature is project-computed with a fixed k
// and cross-checked with `openssl dgst -sha256 -verify`. Hashes are
// SHA-256 of the named message.
static void test_p256(void) {
    uint8_t pub[64];
    uint8_t hash[32];
    uint8_t sig[96];
    unhex("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
          "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
          pub);

    // "sample"
    unhex("af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf", hash);
    size_t n = unhex("3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
                     "022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
                     sig);
    CHECK(p256_ecdsa_verify(pub, hash, sig, n) == 1);

    // Rejections, each a one-bit or one-byte mutation of the vector above.
    hash[0] ^= 0x01;
    CHECK(p256_ecdsa_verify(pub, hash, sig, n) == 0); // flipped hash bit
    hash[0] ^= 0x01;
    sig[6] ^= 0x01;
    CHECK(p256_ecdsa_verify(pub, hash, sig, n) == 0); // flipped r byte
    sig[6] ^= 0x01;
    pub[1] ^= 0x01;
    CHECK(p256_ecdsa_verify(pub, hash, sig, n) == 0); // pub off the curve
    pub[1] ^= 0x01;
    CHECK(p256_ecdsa_verify(pub, hash, sig, n - 1) == 0); // truncated DER
    sig[n] = 0x00;
    CHECK(p256_ecdsa_verify(pub, hash, sig, n + 1) == 0); // trailing garbage

    // Out-of-range scalars: r or s of 0 or n, s kept from the "sample"
    // vector where a live one is needed.
    uint8_t bad[96];
    size_t bad_len = unhex("3026020100"
                           "022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
                           bad);
    CHECK(p256_ecdsa_verify(pub, hash, bad, bad_len) == 0); // r = 0
    bad_len = unhex("3026022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
                    "020100",
                    bad);
    CHECK(p256_ecdsa_verify(pub, hash, bad, bad_len) == 0); // s = 0
    bad_len = unhex("3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
                    "022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
                    bad);
    CHECK(p256_ecdsa_verify(pub, hash, bad, bad_len) == 0); // r = n
    bad_len = unhex("3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
                    "022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                    bad);
    CHECK(p256_ecdsa_verify(pub, hash, bad, bad_len) == 0); // s = n

    // "test"
    unhex("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", hash);
    n = unhex("3045022100f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367"
              "0220019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
              sig);
    CHECK(p256_ecdsa_verify(pub, hash, sig, n) == 1);

    // "chapulin"
    unhex("233f842649c70a89c3c76f0f6cbc3ce8a2e7e853f3a179f9993098098e1451ab", hash);
    n = unhex("30440220515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f"
              "022077ef4265782218e9cdc7fe27f236602794bb2c1a32285ced516bd5d77042d4d0",
              sig);
    CHECK(p256_ecdsa_verify(pub, hash, sig, n) == 1);
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

// ch_connect's config validation: exactly one auth mode, sane buffer. A
// case that passes validation reaches I/O and dies there (empty queue
// gives CH_EIO), which distinguishes it from a rejected config (CH_EINVAL).
// The pin size the compiled build accepts: a P-256 point or an RSA-3072
// modulus. Boundary checks below use it plus each mode's exact limits.
#ifdef CH_PIN_ECDSA
#define TEST_PIN_LEN 64
#else
#define TEST_PIN_LEN 384
#endif

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

static void test_connect_cfg(void) {
    static uint8_t rxbuf[600];
    uint8_t psk[32] = {1};
    uint8_t pin[TEST_PIN_LEN] = {2};
    pin[TEST_PIN_LEN - 1] = 1; // a real RSA modulus is odd
    uint8_t pin2[TEST_PIN_LEN] = {4};
    pin2[TEST_PIN_LEN - 1] = 3; // slot B must be odd too
    mock_io m = {0};
    ch_cfg cfg = {0};
    cfg.buf = rxbuf;
    cfg.buf_len = sizeof rxbuf;
    cfg.send = mock_send;
    cfg.recv = mock_recv;
    cfg.io = &m;
    ch_tls t;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // no auth mode at all
    cfg.psk = psk;
    cfg.psk_len = sizeof psk;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // psk without identity
    cfg.psk_id = (const uint8_t *)"d";
    cfg.psk_id_len = 1;
    cfg.server_pubkey = pin;
    cfg.server_pubkey_len = sizeof pin;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // both modes set
    cfg.server_pubkey = NULL;
    CHECK(ch_connect(&t, &cfg) == CH_EIO); // valid PSK config reaches I/O
    cfg.psk = NULL;
    cfg.psk_len = 0;
    cfg.psk_id = NULL;
    cfg.psk_id_len = 0;
    cfg.server_pubkey = pin;
    CHECK(ch_connect(&t, &cfg) == CH_EIO); // valid pinned config reaches I/O
#ifdef CH_PIN_ECDSA
    cfg.server_pubkey_len = 63;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // P-256 pin must be exactly 64
    cfg.server_pubkey_len = 65;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
#else
    cfg.server_pubkey_len = 256;
    pin[255] = 1; // the low byte the shorter length exposes must be odd too
    CHECK(ch_connect(&t, &cfg) == CH_EIO); // RSA-2048, the smallest pin
    cfg.server_pubkey_len = 248;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // below the floor
    cfg.server_pubkey_len = 392;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // above RSA-3072
    cfg.server_pubkey_len = 260;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // not a multiple of 8 bytes
#endif
    cfg.server_pubkey_len = sizeof pin;
    cfg.buf_len = CH_MIN_RXBUF - 1;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // first size below the floor
    cfg.buf_len = CH_MIN_RXBUF;
    CHECK(ch_connect(&t, &cfg) == CH_EIO); // the floor itself reaches I/O
    cfg.buf_len = sizeof rxbuf;

    // Slot B (key rotation): optional, but bound to every slot-A rule.
    cfg.server_pubkey2 = pin2;
    cfg.server_pubkey2_len = sizeof pin2;
    CHECK(ch_connect(&t, &cfg) == CH_EIO); // both slots valid reaches I/O
    CHECK(t.pin_slot == 0);                // no pin matched anything yet
    cfg.server_pubkey2_len = TEST_PIN_LEN - 1;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // bad slot-B length
    cfg.server_pubkey2_len = sizeof pin2;
    cfg.server_pubkey = NULL;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // slot B never stands alone
    cfg.psk = psk;
    cfg.psk_len = sizeof psk;
    cfg.psk_id = (const uint8_t *)"d";
    cfg.psk_id_len = 1;
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL); // ... not even beside a PSK
    cfg.psk = NULL;
    cfg.psk_len = 0;
    cfg.psk_id = NULL;
    cfg.psk_id_len = 0;
    cfg.server_pubkey = pin;
#ifndef CH_PIN_ECDSA
    pin2[TEST_PIN_LEN - 1] = 2; // even slot B: same corruption check as A
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
    cfg.server_pubkey2 = NULL;
    cfg.server_pubkey2_len = 0;
    pin[TEST_PIN_LEN - 1] = 2; // even low byte: provisioning corruption
    CHECK(ch_connect(&t, &cfg) == CH_EINVAL);
#endif
}

#endif
