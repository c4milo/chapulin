// Session-level tests over a mock transport: the paths e2e cannot steer
// (fragmented post-handshake messages, KeyUpdate both ways, close
// semantics) and ch_connect's config validation. Included by test/unit.c
// only, after its CHECK macro and includes.
#ifndef CH_SESSION_TESTS_H
#define CH_SESSION_TESTS_H

// Mock transport: the "server" is a byte queue we stuff records into.
typedef struct {
    uint8_t data[4096];
    size_t len;
    size_t off;
    int tickets;
    size_t sent; // bytes the client transmitted (KeyUpdate replies etc.)
} mock_io;

static int mock_send(void *io, const uint8_t *p, size_t n) {
    (void)p;
    ((mock_io *)io)->sent += n;
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

static void mock_on_ticket(void *io, const ch_ticket *tk) {
    (void)tk;
    ((mock_io *)io)->tickets++;
}

// Builds a connected session whose read keys mirror srv, fed by m.
static void mock_session(ch_tls *t, mock_io *m, uint8_t *rxbuf, size_t rxlen,
                         const uint8_t secret[SHA256_LEN]) {
    memset(t, 0, sizeof *t);
    t->cfg.buf = rxbuf;
    t->cfg.buf_len = rxlen;
    t->cfg.send = mock_send;
    t->cfg.recv = mock_recv;
    t->cfg.io = m;
    t->cfg.on_ticket = mock_on_ticket;
    memcpy(t->rd_secret, secret, SHA256_LEN);
    rec_dir_init(&t->rd, t->rd_secret);
    uint8_t wsecret[SHA256_LEN];
    ch_rand_bytes(wsecret, sizeof wsecret);
    memcpy(t->wr_secret, wsecret, SHA256_LEN);
    rec_dir_init(&t->wr, t->wr_secret);
    t->state = CH_ST_CONNECTED;
    t->keys = 1;
    t->peer_limit = CH_TX_PT;
}

static void mock_push(mock_io *m, rec_dir *srv, uint8_t type, const uint8_t *pt, size_t n) {
    size_t recn = 0;
    CHECK(rec_seal(srv, type, pt, n, m->data + m->len, sizeof m->data - m->len, &recn) == 0);
    m->len += recn;
}

// Post-handshake behavior the e2e cannot reach: a NewSessionTicket
// fragmented across records (RFC 8446 §5.1), a KeyUpdate that rekeys both
// directions, then application data under the updated key.
static void test_post_handshake(void) {
    uint8_t secret[SHA256_LEN];
    ch_rand_bytes(secret, sizeof secret);
    rec_dir srv;
    rec_dir_init(&srv, secret);
    mock_io m = {0};
    static uint8_t rxbuf[1024];
    ch_tls t;
    mock_session(&t, &m, rxbuf, sizeof rxbuf, secret);

    // NST: lifetime, age_add, nonce(2), identity(90), no extensions.
    uint8_t nst[4 + 105];
    wbuf w;
    wb_init(&w, nst, sizeof nst);
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
    mock_push(&m, &srv, REC_HANDSHAKE, nst, 10);
    mock_push(&m, &srv, REC_HANDSHAKE, nst + 10, w.len - 10);
    // KeyUpdate with update_requested, then data under the updated key.
    const uint8_t ku[5] = {24, 0, 0, 1, 1};
    mock_push(&m, &srv, REC_HANDSHAKE, ku, sizeof ku);
    uint8_t s2[SHA256_LEN];
    memcpy(s2, secret, sizeof s2);
    rec_dir_update(s2, &srv);
    mock_push(&m, &srv, REC_APPDATA, (const uint8_t *)"hola", 4);

    uint8_t out[16];
    int got = ch_read(&t, out, sizeof out);
    CHECK(got == 4 && memcmp(out, "hola", 4) == 0);
    CHECK(m.tickets == 1);
    CHECK(m.sent > 0); // the KeyUpdate reply went out
    CHECK(t.state == CH_ST_CONNECTED);

    // Zero-length reads are a caller bug, never the close sentinel.
    CHECK(ch_read(&t, out, 0) == CH_ECAP);

    // Clean close: exactly one close_notify reply, then 0 forever and no
    // record sealed under wiped keys on a second close.
    const uint8_t close_notify[2] = {1, 0};
    mock_push(&m, &srv, REC_ALERT, close_notify, 2);
    size_t before_close = m.sent;
    CHECK(ch_read(&t, out, sizeof out) == 0);
    CHECK(m.sent > before_close); // our close_notify, under live keys
    size_t after_close = m.sent;
    ch_close(&t);
    CHECK(m.sent == after_close); // keys wiped: nothing more on the wire
    CHECK(ch_read(&t, out, sizeof out) == 0);
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
    size_t bn = unhex("3026020100"
                      "022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
                      bad);
    CHECK(p256_ecdsa_verify(pub, hash, bad, bn) == 0); // r = 0
    bn = unhex("3026022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
               "020100",
               bad);
    CHECK(p256_ecdsa_verify(pub, hash, bad, bn) == 0); // s = 0
    bn = unhex("3046022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
               "022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
               bad);
    CHECK(p256_ecdsa_verify(pub, hash, bad, bn) == 0); // r = n
    bn = unhex("3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
               "022100ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
               bad);
    CHECK(p256_ecdsa_verify(pub, hash, bad, bn) == 0); // s = n

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
// gives CH_EIO), which distinguishes it from a rejected config (CH_ECAP).
static void test_connect_cfg(void) {
    static uint8_t rxbuf[600];
    uint8_t psk[32] = {1};
    uint8_t pin[64] = {2};
    mock_io m = {0};
    ch_cfg cfg = {0};
    cfg.buf = rxbuf;
    cfg.buf_len = sizeof rxbuf;
    cfg.send = mock_send;
    cfg.recv = mock_recv;
    cfg.io = &m;
    ch_tls t;
    CHECK(ch_connect(&t, &cfg) == CH_ECAP); // no auth mode at all
    cfg.psk = psk;
    cfg.psk_len = sizeof psk;
    CHECK(ch_connect(&t, &cfg) == CH_ECAP); // psk without identity
    cfg.psk_id = (const uint8_t *)"d";
    cfg.psk_id_len = 1;
    cfg.server_pubkey = pin;
    CHECK(ch_connect(&t, &cfg) == CH_ECAP); // both modes set
    cfg.server_pubkey = NULL;
    CHECK(ch_connect(&t, &cfg) == CH_EIO); // valid PSK config reaches I/O
    cfg.psk = NULL;
    cfg.psk_len = 0;
    cfg.psk_id = NULL;
    cfg.psk_id_len = 0;
    cfg.server_pubkey = pin;
    CHECK(ch_connect(&t, &cfg) == CH_EIO); // valid pinned config reaches I/O
    cfg.buf_len = 511;
    CHECK(ch_connect(&t, &cfg) == CH_ECAP); // buffer below the floor
}

#endif
