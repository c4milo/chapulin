// The TRUST=webpki session code the chain walk runs inside, over a mock
// transport: ch_connect's config rules at their boundaries, the
// ClientHello's server_name and signature_algorithms bytes, the largest
// hello against CH_HELLO_MAX, and a handshake whose one certificate
// entry is eight bytes of text, which the walk refuses with
// bad_certificate. A flight the walk accepts is bin/webpki_auth_test's,
// which drives hsa_server_auth over a corpus chain instead of a mock
// server, because a mock cannot sign a CertificateVerify over a
// transcript that carries this client's random ClientHello. The
// Makefile builds this file with -DCH_TRUST_WEBPKI over the sources
// that object packages, once classic (bin/webpki_session_test) and once
// under -DCH_KEX_PQ (bin/webpki_session_pq).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "handshake_message.h"
#include "handshake_parser.h"
#include "keysched.h"
#include "record.h"
#include "test_random.h"
#include "tls.h"
#include "webpki.h"
#include "x25519.h"

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#include "hello_exts.h"

// The mock server. send captures the first ClientHello, the retry
// hello and every alert the client sends; recv answers the hello with a
// ServerHello, then EncryptedExtensions and a one-entry Certificate
// under the server handshake keys, and fails once those bytes are read.
// Unless answer is set, recv fails at once, which is how the config
// tests see a config that passed validation: CH_EIO, not CH_EINVAL.
//
// With retry set, recv answers the first hello with a HelloRetryRequest
// instead, carrying a key_share naming retry_group when that is not 0
// and a cookie when retry_cookie is set, and answers the retry hello
// with the flight above. sh_group, when not 0, is the group the
// ServerHello selects whatever the hello it answers carried a share
// for, which is how a row sends a selection the client must refuse.
typedef struct {
    uint8_t hello[CH_TX_STAGE];
    size_t hello_len;
    int retry;
    uint16_t retry_group;
    int retry_cookie;
    uint16_t sh_group;
    uint8_t hrr[96];
    size_t hrr_len;
    uint8_t retry_hello[CH_TX_STAGE];
    size_t retry_hello_len;
    uint8_t retry_record_version; // the low byte of the retry record's legacy_record_version
    int sends;
    int answer; // recv answers the hello; 0 fails recv at once
    int rendered;
    int sni_data; // EncryptedExtensions carries a server_name with one byte of data
    // The ProtocolName an EncryptedExtensions ALPN extension selects,
    // or NULL for a message that carries no ALPN extension.
    const uint8_t *alpn_pick;
    size_t alpn_pick_len;
    uint8_t queue[4096];
    size_t queue_len;
    size_t queue_off;
    rec_dir wr; // server -> client, under s_hs
    rec_dir rd; // client -> server, under c_hs
    int keys;
    uint8_t alert; // description byte of the last alert the client sent
} mock_server;

static const uint8_t server_scalar[X25519_LEN] = {0x07, 0x5e};

// The ML-KEM shared secret's share of the mock's ecdhe buffer: the
// hybrid build puts it ahead of the x25519 one, and a classic build has
// none.
#ifdef CH_KEX_PQ
#define MLKEM_SS_LEN_OR_0 MLKEM_SS_LEN
#else
#define MLKEM_SS_LEN_OR_0 0
#endif

static int mock_send(void *io, const uint8_t *p, size_t n) {
    mock_server *s = io;
    s->sends++;
    if (s->hello_len == 0 && n > REC_HDR && p[0] == REC_HANDSHAKE && n - REC_HDR <= CH_TX_STAGE) {
        memcpy(s->hello, p + REC_HDR, n - REC_HDR);
        s->hello_len = n - REC_HDR;
        return 0;
    }
    if (s->hrr_len > 0 && s->retry_hello_len == 0 && n > REC_HDR && p[0] == REC_HANDSHAKE &&
        n - REC_HDR <= CH_TX_STAGE) {
        memcpy(s->retry_hello, p + REC_HDR, n - REC_HDR);
        s->retry_hello_len = n - REC_HDR;
        s->retry_record_version = p[2];
        return 0;
    }
    if (n == REC_HDR + 2 && p[0] == REC_ALERT) {
        s->alert = p[REC_HDR + 1];
        return 0;
    }
    uint8_t pt[64];
    size_t pt_len = 0;
    uint8_t type = 0;
    if (s->keys && rec_open(&s->rd, p, n, pt, sizeof pt, &pt_len, &type) == 0 &&
        type == REC_ALERT && pt_len == 2) {
        s->alert = pt[1];
    }
    return 0;
}

static void push_clear(mock_server *s, const uint8_t *msg, size_t n) {
    wbuf w;
    wb_init(&w, s->queue + s->queue_len, sizeof s->queue - s->queue_len);
    wb_u8(&w, REC_HANDSHAKE);
    wb_u16(&w, 0x0303);
    wb_u16(&w, (uint16_t)n);
    wb_bytes(&w, msg, n);
    CHECK(!w.err);
    s->queue_len += w.len;
}

static void push_sealed(mock_server *s, const uint8_t *msg, size_t n) {
    size_t out_len = 0;
    CHECK(rec_seal(&s->wr, REC_HANDSHAKE, msg, n, s->queue + s->queue_len,
                   sizeof s->queue - s->queue_len, &out_len) == 0);
    s->queue_len += out_len;
}

// The one KeyShareEntry a captured hello carries: its group, and its
// key_exchange through *key. Returns 0 when the extension is not one
// entry.
static uint16_t hello_share(const uint8_t *hello, size_t n, const uint8_t **key, size_t *key_len) {
    size_t ext_len = 0;
    const uint8_t *ext = hello_ext(hello, n, EXT_KEY_SHARE, &ext_len);
    rbuf r;
    rb_init(&r, ext, ext == NULL ? 0 : ext_len);
    size_t list_len = rb_u16(&r);
    uint16_t group = rb_u16(&r);
    *key_len = rb_u16(&r);
    *key = rb_bytes(&r, *key_len);
    return ext == NULL || r.err || list_len != ext_len - 2 || rb_left(&r) != 0 ? 0 : group;
}

// The ServerHello and the key schedule to the handshake traffic secrets:
// the ecdhe input is the client's own derivation mirrored, over the one
// share the hello answered carries: the ML-KEM shared secret then x25519
// for the hybrid, x25519 alone for x25519.
static void render_server_hello(mock_server *s, sha256 *transcript, const uint8_t *hello,
                                size_t hello_len) {
    const uint8_t *share = NULL;
    size_t share_len = 0;
    uint16_t share_group = hello_share(hello, hello_len, &share, &share_len);
    CHECK(share_group != 0);
    if (share_group == 0) {
        return;
    }
    uint8_t server_pub[X25519_LEN];
    x25519_base(server_pub, server_scalar);
    uint8_t ecdhe[MLKEM_SS_LEN_OR_0 + X25519_LEN];
    size_t ecdhe_len = X25519_LEN;
    uint16_t group = s->sh_group != 0 ? s->sh_group : share_group;
    size_t server_share_len = X25519_LEN;
#ifdef CH_KEX_PQ
    uint8_t ct[MLKEM_CT_LEN];
    if (share_group == CH_GROUP_X25519MLKEM768) {
        static const uint8_t m[32] = {0x4b};
        CHECK(share_len == CH_KEX_CLIENT_SHARE);
        CHECK(mlkem_encaps_derand(ct, ecdhe, share, m) == 0);
        CHECK(x25519(ecdhe + MLKEM_SS_LEN, server_scalar, share + MLKEM_EK_LEN) == 1);
        ecdhe_len = MLKEM_SS_LEN + X25519_LEN;
    }
    if (group == CH_GROUP_X25519MLKEM768) {
        server_share_len = MLKEM_CT_LEN + X25519_LEN;
    }
#endif
    if (share_group == CH_GROUP_X25519) {
        CHECK(share_len == X25519_LEN);
        CHECK(x25519(ecdhe, server_scalar, share) == 1);
    }
    uint8_t msg[128 + CH_KEX_SERVER_SHARE];
    wbuf w;
    wb_init(&w, msg, sizeof msg);
    wb_u8(&w, HS_SERVER_HELLO);
    size_t body = wb_mark(&w, 3);
    wb_u16(&w, 0x0303);
    for (int i = 0; i < 32; i++) {
        wb_u8(&w, 0x42);
    }
    wb_u8(&w, 0);
    wb_u16(&w, SUITE_CHACHA20_POLY1305_SHA256);
    wb_u8(&w, 0);
    size_t exts = wb_mark(&w, 2);
    wb_u16(&w, EXT_SUPPORTED_VERSIONS);
    wb_u16(&w, 2);
    wb_u16(&w, TLS13);
    wb_u16(&w, EXT_KEY_SHARE);
    wb_u16(&w, (uint16_t)(2 + 2 + server_share_len));
    wb_u16(&w, group);
    wb_u16(&w, (uint16_t)server_share_len);
#ifdef CH_KEX_PQ
    if (group == CH_GROUP_X25519MLKEM768) {
        wb_bytes(&w, ct, sizeof ct);
    }
#endif
    wb_bytes(&w, server_pub, sizeof server_pub);
    wb_patch16(&w, exts);
    wb_patch24(&w, body);
    CHECK(!w.err);

    sha256_update(transcript, hello, hello_len);
    sha256_update(transcript, msg, w.len);
    uint8_t hash[SHA256_LEN];
    sha256 snapshot = *transcript;
    sha256_final(&snapshot, hash);
    static const uint8_t no_psk[SHA256_LEN] = {0};
    uint8_t early[SHA256_LEN];
    uint8_t binder[SHA256_LEN];
    uint8_t handshake_secret[SHA256_LEN];
    uint8_t c_hs[SHA256_LEN];
    uint8_t s_hs[SHA256_LEN];
    ks_early(no_psk, sizeof no_psk, 0, early, binder);
    ks_handshake(early, ecdhe, ecdhe_len, hash, handshake_secret, c_hs, s_hs);
    push_clear(s, msg, w.len);
    rec_dir_init(&s->wr, s_hs);
    rec_dir_init(&s->rd, c_hs);
    s->keys = 1;
}

// EncryptedExtensions: the empty server_name acknowledgement this build
// admits, and an ALPN selection when the case asked for one (RFC 7301
// §3.2). sni_data puts one byte of data in the acknowledgement, which
// the parser refuses as a body of the wrong length.
static void push_encrypted_exts(mock_server *s) {
    uint8_t msg[64];
    wbuf w;
    wb_init(&w, msg, sizeof msg);
    wb_u8(&w, HS_ENCRYPTED_EXTENSIONS);
    size_t body = wb_mark(&w, 3);
    size_t exts = wb_mark(&w, 2);
    wb_u16(&w, EXT_SERVER_NAME);
    wb_u16(&w, s->sni_data ? 1 : 0);
    if (s->sni_data) {
        wb_u8(&w, 'x');
    }
    if (s->alpn_pick != NULL) {
        wb_u16(&w, EXT_ALPN);
        wb_u16(&w, (uint16_t)(2 + 1 + s->alpn_pick_len));
        wb_u16(&w, (uint16_t)(1 + s->alpn_pick_len)); // ProtocolNameList length
        wb_u8(&w, (uint8_t)s->alpn_pick_len);
        wb_bytes(&w, s->alpn_pick, s->alpn_pick_len);
    }
    wb_patch16(&w, exts);
    wb_patch24(&w, body);
    CHECK(!w.err);
    push_sealed(s, msg, w.len);
}

// A HelloRetryRequest (RFC 9846 §4.2.4): the ServerHello layout with
// the fixed random, carrying supported_versions, a key_share naming
// retry_group when that is not 0, and a four-byte cookie when
// retry_cookie is set. The mock keeps its bytes for the transcript.
static void push_retry(mock_server *s) {
    wbuf w;
    wb_init(&w, s->hrr, sizeof s->hrr);
    wb_u8(&w, HS_SERVER_HELLO);
    size_t body = wb_mark(&w, 3);
    wb_u16(&w, 0x0303);
    wb_bytes(&w, hsp_hrr_magic, 32);
    wb_u8(&w, 0);
    wb_u16(&w, SUITE_CHACHA20_POLY1305_SHA256);
    wb_u8(&w, 0);
    size_t exts = wb_mark(&w, 2);
    wb_u16(&w, EXT_SUPPORTED_VERSIONS);
    wb_u16(&w, 2);
    wb_u16(&w, TLS13);
    if (s->retry_group != 0) {
        wb_u16(&w, EXT_KEY_SHARE);
        wb_u16(&w, 2);
        wb_u16(&w, s->retry_group);
    }
    if (s->retry_cookie) {
        wb_u16(&w, EXT_COOKIE);
        wb_u16(&w, 2 + 4);
        wb_u16(&w, 4);
        wb_bytes(&w, (const uint8_t *)"cook", 4);
    }
    wb_patch16(&w, exts);
    wb_patch24(&w, body);
    CHECK(!w.err);
    s->hrr_len = w.len;
    push_clear(s, s->hrr, s->hrr_len);
}

// That message, and a Certificate whose one entry is eight bytes that
// are no certificate: the walk refuses them as malformed DER and the
// session fails closed. After a retry the transcript opens with RFC
// 9846 §4.4.1's message_hash over the first hello, then the retry, and
// the ServerHello answers the retry hello.
static void render_flight(mock_server *s) {
    sha256 transcript;
    sha256_init(&transcript);
    if (s->hrr_len > 0) {
        uint8_t ch1[SHA256_LEN];
        sha256 first;
        sha256_init(&first);
        sha256_update(&first, s->hello, s->hello_len);
        sha256_final(&first, ch1);
        const uint8_t synth[4] = {HS_MESSAGE_HASH, 0, 0, SHA256_LEN};
        sha256_update(&transcript, synth, sizeof synth);
        sha256_update(&transcript, ch1, sizeof ch1);
        sha256_update(&transcript, s->hrr, s->hrr_len);
        render_server_hello(s, &transcript, s->retry_hello, s->retry_hello_len);
    } else {
        render_server_hello(s, &transcript, s->hello, s->hello_len);
    }
    push_encrypted_exts(s);
    static const uint8_t cert[] = {HS_CERTIFICATE,
                                   0,
                                   0,
                                   17,
                                   0,
                                   0,
                                   0,
                                   13,
                                   0,
                                   0,
                                   8,
                                   'c',
                                   'h',
                                   'a',
                                   'p',
                                   'u',
                                   'l',
                                   'i',
                                   'n',
                                   0,
                                   0};
    push_sealed(s, cert, sizeof cert);
}

static int mock_recv(void *io, uint8_t *p, size_t n) {
    mock_server *s = io;
    if (!s->answer || s->hello_len == 0) {
        return -1;
    }
    if (s->retry && s->hrr_len == 0) {
        push_retry(s);
    } else if (!s->rendered && (s->hrr_len == 0 || s->retry_hello_len > 0)) {
        s->rendered = 1;
        render_flight(s);
    }
    size_t left = s->queue_len - s->queue_off;
    if (left == 0) {
        return -1;
    }
    size_t take = n < left ? n : left;
    memcpy(p, s->queue + s->queue_off, take);
    s->queue_off += take;
    return (int)take;
}

// A valid TRUST=webpki config: two anchors, a hostname and a clock. It
// offers no ALPN protocol, which is legal and sends no extension; the
// ALPN rows set the two fields themselves.
static uint8_t rxbuf[CH_MIN_RXBUF];
static const uint8_t anchor_der[] = {0x30, 0x00};
static ch_trust_anchor anchors[CH_WEBPKI_ANCHOR_MAX + 1];
static const uint8_t host[] = {'s', '3', '.', 'e', 'x', 'a', 'm', 'p',
                               'l', 'e', '.', 't', 'e', 's', 't'};

// The ALPN offer the rows configure, one entry past the cap so a row
// can offer one too many. Entry 0 is "h2" and entry 1 is "http/1.1",
// the two names an HTTP client offers; the rest are distinct two-byte
// filler names, because ch_connect refuses a repeated name.
static const uint8_t alpn_h2[] = {'h', '2'};
static const uint8_t alpn_http11[] = {'h', 't', 't', 'p', '/', '1', '.', '1'};
static uint8_t alpn_filler[CH_ALPN_MAX][2];
static ch_alpn_protocol alpn[CH_ALPN_MAX + 1];

static void fill_alpn(void) {
    alpn[0] = (ch_alpn_protocol){alpn_h2, sizeof alpn_h2};
    alpn[1] = (ch_alpn_protocol){alpn_http11, sizeof alpn_http11};
    for (size_t i = 2; i < sizeof alpn / sizeof alpn[0]; i++) {
        alpn_filler[i - 2][0] = 'p';
        alpn_filler[i - 2][1] = (uint8_t)('0' + i);
        alpn[i] = (ch_alpn_protocol){alpn_filler[i - 2], 2};
    }
}

static ch_cfg valid_cfg(mock_server *s) {
    for (size_t i = 0; i < sizeof anchors / sizeof anchors[0]; i++) {
        anchors[i] =
            (ch_trust_anchor){anchor_der, sizeof anchor_der, anchor_der, sizeof anchor_der};
    }
    fill_alpn();
    memset(s, 0, sizeof *s);
    ch_cfg cfg = {0};
    cfg.buf = rxbuf;
    cfg.buf_len = sizeof rxbuf;
    cfg.send = mock_send;
    cfg.recv = mock_recv;
    cfg.io = s;
    cfg.anchors = anchors;
    cfg.anchor_count = 2;
    cfg.hostname = host;
    cfg.hostname_len = sizeof host;
    cfg.now_seconds = 1789000000U;
    return cfg;
}

// Runs ch_connect on cfg and reports whether it was refused before a
// byte left: CH_EINVAL with no send.
static int refused(const ch_cfg *cfg) {
    ch_tls t;
    const mock_server *s = cfg->io;
    int rc = ch_connect(&t, cfg);
    return rc == CH_EINVAL && s->sends == 0;
}

// Runs ch_connect on cfg and reports whether it passed the config check:
// the client sent its ClientHello, and recv's failure then returned
// CH_EIO.
static int sends_client_hello(const ch_cfg *cfg) {
    ch_tls t;
    const mock_server *s = cfg->io;
    int rc = ch_connect(&t, cfg);
    return rc == CH_EIO && s->hello_len > 0;
}

#include "rxbuf_floor_tests.h"
#include "webpki_groups_cases.h"
#include "webpki_session_cases.h"

int main(void) {
    test_webpki_cfg_anchors();
    test_webpki_cfg_clock();
    test_webpki_cfg_hostname();
    test_webpki_cfg_other_modes();
    test_rxbuf_floor();
    test_webpki_cfg_alpn_count();
    test_webpki_cfg_alpn_names();
    test_webpki_hello();
    test_webpki_hello_alpn();
    test_webpki_hello_boundary();
    test_webpki_handshake_fails_closed();
    test_webpki_handshake_reports_alpn();
    test_webpki_retry_names_shared_group();
#ifdef CH_KEX_TWO_GROUPS
    test_webpki_groups_hello();
    test_webpki_retry_to_x25519();
    test_webpki_retry_refusals();
#endif
    if (failures > 0) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)printf("webpki_session_test: all checks passed\n");
    return 0;
}
