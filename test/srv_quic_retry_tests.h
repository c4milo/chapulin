// The QUIC server's HelloRetryRequest round over the two ClientHellos
// ngtcp2's interop client sent colibri's server (test/srv_quic_retry_vectors.h).
// ngtcp2's second hello carries the same extensions as its first in another
// order, and the server refused it until the frozen digest compared the
// extensions as a set (docs/decisions.md 59). It uses CHECK, unhex,
// provision, cookie_key and server_params from test/srv_quic_test.c and is
// included after them.
//
// The recorded second hello carries a cookie colibri's server minted under
// its own key, which no server here opens. So each case writes the cookie
// this server minted for the recorded first hello over the recorded one,
// which is the same length, and every other byte stays ngtcp2's. The cookie
// is the same in every case: srv_cookie_mint draws no randomness, and the
// first hello and the key are fixed. The case that completes the handshake
// also writes its own key share over ngtcp2's, because this test holds no
// private key for ngtcp2's. Both are fields RFC 9846 §4.2.2 lets the second
// hello change (rfc9846.txt:1191-1213), so neither enters the digest.
#ifndef CH_SRV_QUIC_RETRY_TESTS_H
#define CH_SRV_QUIC_RETRY_TESTS_H

#include "buf.h"
#include "keysched.h"
#include "mlkem.h"
#include "srv_quic_retry_vectors.h"
#include "x25519.h"

// Room for the recorded second hello, 1,566 bytes, and the largest variant.
#define RETRY_HELLO_CAP 2048
// Room for what the server writes at one level.
#define RETRY_OUT_CAP 4096
// The recorded hellos carry ten and eleven extensions.
#define RETRY_EXT_MAX 16
// The HelloRetryRequest bytes before the frozen digest in its cookie: the
// message up to the cookie's body (62 bytes), then the cookie's version,
// suite and group (5) and Hash(ClientHello1) (32). Only the digest and the
// MAC after it may differ from colibri's server's.
#define RETRY_BEFORE_FROZEN (62 + 5 + SHA256_LEN)
// Where key_exchange starts inside the key_share extension: type, length,
// client_shares length, group and key_exchange length, two bytes each.
#define KEY_SHARE_EXCHANGE_AT 10

// One handshake message, header included.
typedef struct {
    uint8_t bytes[RETRY_HELLO_CAP];
    size_t len;
} retry_msg;

// What the server wrote, per level, in order.
static struct {
    uint8_t bytes[3][RETRY_OUT_CAP];
    size_t len[3];
} retry_out;

static int retry_sink(void *io, uint8_t level, const uint8_t *p, size_t n) {
    (void)io;
    if (level >= 3 || retry_out.len[level] + n > RETRY_OUT_CAP) {
        return -1;
    }
    memcpy(retry_out.bytes[level] + retry_out.len[level], p, n);
    retry_out.len[level] += n;
    return 0;
}

static void retry_level_ready(void *io, uint8_t level, uint8_t direction) {
    (void)io;
    (void)level;
    (void)direction;
}

// ngtcp2 offers one protocol, and the server must offer it too, or the
// first hello fails with no_application_protocol before any retry.
static const uint8_t alpn_hq_interop[] = {'h', 'q', '-', 'i', 'n', 't', 'e', 'r', 'o', 'p'};
static const ch_alpn_protocol retry_alpn[1] = {
    {alpn_hq_interop, sizeof alpn_hq_interop}
};
static uint8_t retry_rxbuf[RETRY_HELLO_CAP];

// A ClientHello split into its head, legacy_version through
// legacy_compression_methods, and its extensions, each whole: type,
// length and body. Every pointer points into the message it was split
// from, or into a buffer a case owns.
typedef struct {
    const uint8_t *head;
    size_t head_len;
    const uint8_t *ext[RETRY_EXT_MAX];
    size_t ext_len[RETRY_EXT_MAX];
    size_t count;
} hello_parts;

static void from_hex(retry_msg *m, const char *hex) {
    m->len = 0;
    CHECK(strlen(hex) / 2 <= sizeof m->bytes);
    if (strlen(hex) / 2 <= sizeof m->bytes) {
        m->len = unhex(hex, m->bytes);
    }
}

static void split_hello(const retry_msg *m, hello_parts *parts) {
    memset(parts, 0, sizeof *parts);
    rbuf r;
    rb_init(&r, m->bytes + 4, m->len - 4);
    rb_skip(&r, 2 + SRV_RANDOM);
    rb_skip(&r, rb_u8(&r));
    rb_skip(&r, rb_u16(&r));
    rb_skip(&r, rb_u8(&r));
    parts->head = m->bytes + 4;
    parts->head_len = m->len - 4 - rb_left(&r);
    rb_skip(&r, 2);
    parts->count = 0;
    while (rb_left(&r) > 0 && parts->count < RETRY_EXT_MAX) {
        const uint8_t *ext = rb_bytes(&r, 0);
        (void)rb_u16(&r);
        size_t len = rb_u16(&r);
        rb_skip(&r, len);
        parts->ext[parts->count] = ext;
        parts->ext_len[parts->count] = 4 + len;
        parts->count++;
    }
    CHECK(!r.err && rb_left(&r) == 0);
}

static void join_hello(retry_msg *m, const hello_parts *parts) {
    wbuf w;
    wb_init(&w, m->bytes, sizeof m->bytes);
    wb_u8(&w, HS_CLIENT_HELLO);
    size_t body_at = wb_mark(&w, 3);
    wb_bytes(&w, parts->head, parts->head_len);
    size_t block_at = wb_mark(&w, 2);
    for (size_t i = 0; i < parts->count; i++) {
        wb_bytes(&w, parts->ext[i], parts->ext_len[i]);
    }
    wb_patch16(&w, block_at);
    wb_patch24(&w, body_at);
    CHECK(!w.err);
    m->len = w.len;
}

// The index of the extension of this type, or parts->count.
static size_t ext_at(const hello_parts *parts, uint16_t type) {
    for (size_t i = 0; i < parts->count; i++) {
        if (((uint16_t)(parts->ext[i][0] << 8) | parts->ext[i][1]) == type) {
            return i;
        }
    }
    return parts->count;
}

// The body of one extension of a ServerHello-shaped message, msg_len bytes
// with its header, and its length in *body_len; NULL when it carries none.
static const uint8_t *server_ext(const uint8_t *msg, size_t msg_len, uint16_t type,
                                 size_t *body_len) {
    if (msg_len < 4) {
        return NULL;
    }
    rbuf r;
    rb_init(&r, msg + 4, msg_len - 4);
    rb_skip(&r, 2 + SRV_RANDOM);
    rb_skip(&r, rb_u8(&r));
    rb_skip(&r, 2 + 1 + 2);
    while (rb_left(&r) > 0 && !r.err) {
        uint16_t ext_type = rb_u16(&r);
        size_t len = rb_u16(&r);
        const uint8_t *body = rb_bytes(&r, len);
        if (body != NULL && ext_type == type) {
            *body_len = len;
            return body;
        }
    }
    return NULL;
}

// The length of the handshake message at p, header included, out of n
// bytes, or 0 when fewer than a whole message remain.
static size_t message_len(const uint8_t *p, size_t n) {
    if (n < 4) {
        return 0;
    }
    size_t len = 4 + ((size_t)p[1] << 16 | (size_t)p[2] << 8 | p[3]);
    return len <= n ? len : 0;
}

// A server as colibri's interop image configures one, with this binary's
// identities and cookie key, and nothing written yet.
static void retry_session(ch_quic *q) {
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.buf = retry_rxbuf;
    cfg.buf_len = sizeof retry_rxbuf;
    cfg.alpn_protocols = retry_alpn;
    cfg.alpn_count = 1;
    cfg.on_level_ready = retry_level_ready;
    cfg.transport_params = server_params;
    cfg.transport_params_len = sizeof server_params;
    cfg.srv.cookie_key = cookie_key;
    cfg.srv.on_crypto_out = retry_sink;
    provision(&cfg);
    memset(&retry_out, 0, sizeof retry_out);
    CHECK(ch_srv_quic_init(q, &cfg) == CH_OK);
}

// The recorded first hello into a fresh server. The answer is a
// HelloRetryRequest that asks for X25519MLKEM768, and it matches colibri's
// server's byte for byte up to the frozen digest in its cookie, so the
// replay reproduces the round colibri recorded. The cookie it carries is
// written to cookie.
static void first_round(ch_quic *q, uint8_t cookie[SRV_COOKIE_MAX], size_t *cookie_len) {
    retry_session(q);
    retry_msg hello1;
    retry_msg colibri;
    from_hex(&hello1, ngtcp2_hello1_hex);
    from_hex(&colibri, colibri_retry_hex);
    CHECK(hello1.len == 275 && colibri.len == 163);
    CHECK(ch_srv_quic_crypto_in(q, CH_LEVEL_INITIAL, hello1.bytes, hello1.len) == CH_OK);
    CHECK(ch_quic_state(q) == CH_ST_START);
    const uint8_t *hrr = retry_out.bytes[CH_LEVEL_INITIAL];
    CHECK(retry_out.len[CH_LEVEL_INITIAL] == colibri.len);
    CHECK(memcmp(hrr, colibri.bytes, RETRY_BEFORE_FROZEN) == 0);
    size_t group_len = 0;
    const uint8_t *group = server_ext(hrr, colibri.len, EXT_KEY_SHARE, &group_len);
    CHECK(group != NULL && group_len == 2 && group[0] == 0x11 && group[1] == 0xec);
    size_t body_len = 0;
    const uint8_t *body = server_ext(hrr, colibri.len, EXT_COOKIE, &body_len);
    CHECK(body != NULL && body_len == 2 + SRV_COOKIE_MAX - (SRV_COOKIE_HASH_MAX - SHA256_LEN));
    *cookie_len = body_len - 2;
    memcpy(cookie, body + 2, *cookie_len);
}

// The recorded second hello with the cookie this server minted in place of
// colibri's and, when share is not NULL, that key_exchange in place of
// ngtcp2's. The two replacements keep every length, so every other byte is
// ngtcp2's, in ngtcp2's order.
static void recorded_second(retry_msg *m, const uint8_t *cookie, size_t cookie_len,
                            const uint8_t share[CH_HYBRID_CLIENT_SHARE]) {
    from_hex(m, ngtcp2_hello2_hex);
    CHECK(m->len == 1566);
    hello_parts parts;
    split_hello(m, &parts);
    size_t at = ext_at(&parts, EXT_COOKIE);
    CHECK(at < parts.count && parts.ext_len[at] == 6 + cookie_len);
    memcpy(m->bytes + (parts.ext[at] - m->bytes) + 6, cookie, cookie_len);
    if (share != NULL) {
        at = ext_at(&parts, EXT_KEY_SHARE);
        CHECK(at < parts.count &&
              parts.ext_len[at] == KEY_SHARE_EXCHANGE_AT + CH_HYBRID_CLIENT_SHARE);
        memcpy(m->bytes + (parts.ext[at] - m->bytes) + KEY_SHARE_EXCHANGE_AT, share,
               CH_HYBRID_CLIENT_SHARE);
    }
}

// One retry round against a fresh server, reporting what the server
// answered the second hello with and the alert it left.
static int retry_answer(const retry_msg *hello2, uint8_t *alert) {
    static ch_quic q;
    uint8_t cookie[SRV_COOKIE_MAX];
    size_t cookie_len = 0;
    first_round(&q, cookie, &cookie_len);
    int rc = ch_srv_quic_crypto_in(&q, CH_LEVEL_INITIAL, hello2->bytes, hello2->len);
    *alert = ch_quic_alert(&q);
    return rc;
}

// Whether the server refuses hello2 with illegal_parameter.
static int retry_refused(const retry_msg *hello2) {
    uint8_t alert = 0;
    return retry_answer(hello2, &alert) == CH_EPROTO && alert == ALERT_ILLEGAL_PARAMETER;
}

// The boundary pairs around the frozen digest, each a variant of ngtcp2's
// second hello. The same extensions in the first hello's order and in
// ngtcp2's are accepted. One covered byte changed, one covered extension
// dropped, one added, one head byte changed and one extension sent twice
// are each refused with illegal_parameter.
static void test_retry_boundaries(const uint8_t *cookie, size_t cookie_len) {
    retry_msg hello1;
    retry_msg hello2;
    retry_msg variant;
    uint8_t alert = 0;
    from_hex(&hello1, ngtcp2_hello1_hex);
    recorded_second(&hello2, cookie, cookie_len, NULL);
    hello_parts first;
    hello_parts second;
    split_hello(&hello1, &first);
    split_hello(&hello2, &second);

    // ngtcp2's order, with ngtcp2's own hybrid share: the round that failed.
    CHECK(retry_answer(&hello2, &alert) == CH_OK);
    CHECK(retry_out.len[CH_LEVEL_HANDSHAKE] > 0);

    // The first hello's order, the hybrid share in the x25519 share's
    // place and the cookie after the last extension: a client that
    // reorders nothing.
    hello_parts same = first;
    size_t at = ext_at(&same, EXT_KEY_SHARE);
    same.ext[at] = second.ext[ext_at(&second, EXT_KEY_SHARE)];
    same.ext_len[at] = second.ext_len[ext_at(&second, EXT_KEY_SHARE)];
    same.ext[same.count] = second.ext[ext_at(&second, EXT_COOKIE)];
    same.ext_len[same.count] = second.ext_len[ext_at(&second, EXT_COOKIE)];
    same.count++;
    join_hello(&variant, &same);
    CHECK(retry_answer(&variant, &alert) == CH_OK);

    // One byte of quic_transport_parameters, an extension the server reads
    // none of, so only the digest can refuse it.
    hello_parts changed = second;
    at = ext_at(&changed, EXT_QUIC_TRANSPORT_PARAMS);
    uint8_t params[RETRY_HELLO_CAP];
    memcpy(params, changed.ext[at], changed.ext_len[at]);
    params[changed.ext_len[at] - 1] ^= 0x01;
    changed.ext[at] = params;
    join_hello(&variant, &changed);
    CHECK(retry_refused(&variant));

    // session_ticket (0x0023) dropped: an extension the server does not
    // recognize, which the digest covers all the same.
    hello_parts removed = second;
    CHECK(ext_at(&removed, 0x0023) == removed.count - 1);
    removed.count--;
    join_hello(&variant, &removed);
    CHECK(retry_refused(&variant));

    // An unknown extension added.
    static const uint8_t unknown[] = {0x2a, 0x2a, 0x00, 0x00};
    hello_parts added = second;
    added.ext[added.count] = unknown;
    added.ext_len[added.count] = sizeof unknown;
    added.count++;
    join_hello(&variant, &added);
    CHECK(retry_refused(&variant));

    // One byte of the random.
    hello_parts head = second;
    uint8_t head_bytes[RETRY_HELLO_CAP];
    memcpy(head_bytes, head.head, head.head_len);
    head_bytes[2] ^= 0x01;
    head.head = head_bytes;
    join_hello(&variant, &head);
    CHECK(retry_refused(&variant));

    // encrypt_then_mac (0x0016) twice, byte for byte. The ascending walk
    // would add only the first, so the digest alone would accept this;
    // the parser's duplicate refusal is what stops it.
    hello_parts twice = second;
    at = ext_at(&twice, 0x0016);
    twice.ext[twice.count] = twice.ext[at];
    twice.ext_len[twice.count] = twice.ext_len[at];
    twice.count++;
    join_hello(&variant, &twice);
    CHECK(retry_refused(&variant));
}

// The transcript hash over what the server and ngtcp2 have exchanged, in
// RFC 9846 §4.1's retry form: message_hash over the first hello, then
// the HelloRetryRequest, then the messages given (rfc9846.txt:1084-1087).
static void retry_transcript(const retry_msg *hello1, const uint8_t *msgs, size_t msgs_len,
                             uint8_t out[SHA256_LEN]) {
    uint8_t hello1_hash[SHA256_LEN];
    sha256_of(hello1->bytes, hello1->len, hello1_hash);
    const uint8_t synth[4] = {HS_MESSAGE_HASH, 0, 0, SHA256_LEN};
    sha256 t;
    sha256_init(&t);
    sha256_update(&t, synth, sizeof synth);
    sha256_update(&t, hello1_hash, sizeof hello1_hash);
    sha256_update(&t, msgs, msgs_len);
    sha256_final(&t, out);
}

// The whole handshake over ngtcp2's reordered second hello, with this
// test's own hybrid key pair in it: the server's ServerHello, its
// Finished, which this test checks from its own key schedule, and the
// client Finished computed the same way, which the server accepts. Both
// sides then hashed the same bytes, the reordered hello included.
static void test_retry_completes(const uint8_t *cookie, size_t cookie_len) {
    uint8_t d[32];
    uint8_t z[32];
    uint8_t x25519_priv[X25519_LEN];
    memset(d, 0x31, sizeof d);
    memset(z, 0x32, sizeof z);
    memset(x25519_priv, 0x33, sizeof x25519_priv);
    static uint8_t share[CH_HYBRID_CLIENT_SHARE];
    static uint8_t dk[MLKEM_DK_LEN];
    mlkem_keygen_derand(share, dk, d, z);
    x25519_base(share + MLKEM_EK_LEN, x25519_priv);

    static ch_quic q;
    uint8_t minted[SRV_COOKIE_MAX];
    size_t minted_len = 0;
    first_round(&q, minted, &minted_len);
    CHECK(minted_len == cookie_len && memcmp(minted, cookie, cookie_len) == 0);
    retry_msg hello1;
    retry_msg hello2;
    from_hex(&hello1, ngtcp2_hello1_hex);
    recorded_second(&hello2, cookie, cookie_len, share);
    int rc = ch_srv_quic_crypto_in(&q, CH_LEVEL_INITIAL, hello2.bytes, hello2.len);
    CHECK(rc == CH_OK);
    if (rc != CH_OK) {
        return;
    }

    // Initial holds the HelloRetryRequest, then the ServerHello.
    const uint8_t *initial = retry_out.bytes[CH_LEVEL_INITIAL];
    size_t hrr_len = message_len(initial, retry_out.len[CH_LEVEL_INITIAL]);
    const uint8_t *sh = initial + hrr_len;
    size_t sh_len = message_len(sh, retry_out.len[CH_LEVEL_INITIAL] - hrr_len);
    CHECK(hrr_len > 0 && sh_len > 0 && hrr_len + sh_len == retry_out.len[CH_LEVEL_INITIAL]);
    size_t server_share_len = 0;
    const uint8_t *server_share = server_ext(sh, sh_len, EXT_KEY_SHARE, &server_share_len);
    CHECK(server_share != NULL && server_share_len == 4 + CH_HYBRID_SERVER_SHARE);
    if (server_share == NULL || server_share_len != 4 + CH_HYBRID_SERVER_SHARE) {
        return;
    }
    // RFC 10024: the ML-KEM secret, then the x25519 one.
    uint8_t ikm[MLKEM_SS_LEN + X25519_LEN];
    mlkem_decaps(ikm, server_share + 4, dk);
    CHECK(x25519(ikm + MLKEM_SS_LEN, x25519_priv, server_share + 4 + MLKEM_CT_LEN) == 1);

    // The transcript through the ServerHello, then through each Handshake
    // message: EncryptedExtensions, Certificate, CertificateVerify and
    // the server Finished, which is the last.
    static uint8_t exchanged[RETRY_HELLO_CAP + 2 * RETRY_OUT_CAP];
    wbuf w;
    wb_init(&w, exchanged, sizeof exchanged);
    wb_bytes(&w, initial, hrr_len);
    wb_bytes(&w, hello2.bytes, hello2.len);
    wb_bytes(&w, sh, sh_len);
    uint8_t hash[SHA256_LEN];
    retry_transcript(&hello1, exchanged, w.len, hash);
    uint8_t early[SHA256_LEN];
    uint8_t binder_key[SHA256_LEN];
    uint8_t handshake_secret[SHA256_LEN];
    uint8_t c_hs[SHA256_LEN];
    uint8_t s_hs[SHA256_LEN];
    static const uint8_t no_psk[SHA256_LEN] = {0};
    ks_early(no_psk, sizeof no_psk, 0, early, binder_key);
    ks_handshake(early, ikm, sizeof ikm, hash, handshake_secret, c_hs, s_hs);

    const uint8_t *flight = retry_out.bytes[CH_LEVEL_HANDSHAKE];
    size_t flight_len = retry_out.len[CH_LEVEL_HANDSHAKE];
    size_t off = 0;
    size_t len = message_len(flight, flight_len);
    while (len > 0 && off + len < flight_len) {
        wb_bytes(&w, flight + off, len);
        off += len;
        len = message_len(flight + off, flight_len - off);
    }
    CHECK(!w.err && len == 4 + SHA256_LEN && off + len == flight_len);
    CHECK(flight[off] == HS_FINISHED);
    retry_transcript(&hello1, exchanged, w.len, hash);
    uint8_t want[SHA256_LEN];
    ks_verify_data(s_hs, hash, want);
    CHECK(memcmp(flight + off + 4, want, sizeof want) == 0);

    wb_bytes(&w, flight + off, len);
    retry_transcript(&hello1, exchanged, w.len, hash);
    uint8_t finished[4 + SHA256_LEN] = {HS_FINISHED, 0, 0, SHA256_LEN};
    ks_verify_data(c_hs, hash, finished + 4);
    CHECK(ch_srv_quic_crypto_in(&q, CH_LEVEL_HANDSHAKE, finished, sizeof finished) == CH_OK);
    CHECK(ch_quic_state(&q) == CH_ST_CONNECTED);
}

static void test_ngtcp2_retry(void) {
    static ch_quic q;
    uint8_t cookie[SRV_COOKIE_MAX];
    size_t cookie_len = 0;
    first_round(&q, cookie, &cookie_len);
    test_retry_boundaries(cookie, cookie_len);
    test_retry_completes(cookie, cookie_len);
}

#endif
