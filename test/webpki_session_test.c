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

// The mock server. send captures the first ClientHello and every alert
// the client sends; recv answers the hello with a ServerHello, then
// EncryptedExtensions and a one-entry Certificate under the server
// handshake keys, and fails once those bytes are read. Unless answer is
// set, recv fails at once, which is how the config tests see a config
// that passed validation: CH_EIO, not CH_EINVAL.
typedef struct {
    uint8_t hello[CH_TX_STAGE];
    size_t hello_len;
    int sends;
    int answer; // recv answers the hello; 0 fails recv at once
    int rendered;
    int sni_data; // EncryptedExtensions carries a server_name with one byte of data
    uint8_t queue[4096];
    size_t queue_len;
    size_t queue_off;
    rec_dir wr; // server -> client, under s_hs
    rec_dir rd; // client -> server, under c_hs
    int keys;
    uint8_t alert; // description byte of the last alert the client sent
} mock_server;

static const uint8_t server_scalar[X25519_LEN] = {0x07, 0x5e};

static int mock_send(void *io, const uint8_t *p, size_t n) {
    mock_server *s = io;
    s->sends++;
    if (s->hello_len == 0 && n > REC_HDR && p[0] == REC_HANDSHAKE && n - REC_HDR <= CH_TX_STAGE) {
        memcpy(s->hello, p + REC_HDR, n - REC_HDR);
        s->hello_len = n - REC_HDR;
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

// The ServerHello and the key schedule to the handshake traffic secrets:
// the ecdhe input is the client's own derivation mirrored, the ML-KEM
// shared secret then x25519 under KEX=pq, x25519 alone otherwise.
static void render_server_hello(mock_server *s, sha256 *transcript) {
    size_t share_len = 0;
    const uint8_t *share = hello_ext(s->hello, s->hello_len, EXT_KEY_SHARE, &share_len);
    CHECK(share != NULL && share_len == 6 + CH_KEX_CLIENT_SHARE);
    if (share == NULL || share_len != 6 + CH_KEX_CLIENT_SHARE) {
        return;
    }
    share += 6; // client_shares length, group, key_exchange length
    uint8_t server_pub[X25519_LEN];
    x25519_base(server_pub, server_scalar);
#ifdef CH_KEX_PQ
    static const uint8_t m[32] = {0x4b};
    uint8_t ct[MLKEM_CT_LEN];
    uint8_t ecdhe[MLKEM_SS_LEN + X25519_LEN];
    CHECK(mlkem_encaps_derand(ct, ecdhe, share, m) == 0);
    CHECK(x25519(ecdhe + MLKEM_SS_LEN, server_scalar, share + MLKEM_EK_LEN) == 1);
#else
    uint8_t ecdhe[X25519_LEN];
    CHECK(x25519(ecdhe, server_scalar, share) == 1);
#endif
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
    wb_u16(&w, 2 + 2 + CH_KEX_SERVER_SHARE);
    wb_u16(&w, CH_KEX_GROUP);
    wb_u16(&w, CH_KEX_SERVER_SHARE);
#ifdef CH_KEX_PQ
    wb_bytes(&w, ct, sizeof ct);
#endif
    wb_bytes(&w, server_pub, sizeof server_pub);
    wb_patch16(&w, exts);
    wb_patch24(&w, body);
    CHECK(!w.err);

    sha256_update(transcript, s->hello, s->hello_len);
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
    ks_handshake(early, ecdhe, sizeof ecdhe, hash, handshake_secret, c_hs, s_hs);
    push_clear(s, msg, w.len);
    rec_dir_init(&s->wr, s_hs);
    rec_dir_init(&s->rd, c_hs);
    s->keys = 1;
}

// EncryptedExtensions with a server_name acknowledgement, and a
// Certificate whose one entry is eight bytes that are no certificate:
// the walk refuses them as malformed DER and the session fails closed.
static void render_flight(mock_server *s) {
    sha256 transcript;
    sha256_init(&transcript);
    render_server_hello(s, &transcript);
    if (s->sni_data) {
        static const uint8_t ee[] = {HS_ENCRYPTED_EXTENSIONS, 0, 0, 7, 0, 5, 0, 0, 0, 1, 'x'};
        push_sealed(s, ee, sizeof ee);
    } else {
        static const uint8_t ee[] = {HS_ENCRYPTED_EXTENSIONS, 0, 0, 6, 0, 4, 0, 0, 0, 0};
        push_sealed(s, ee, sizeof ee);
    }
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
    if (!s->rendered) {
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

// A valid TRUST=webpki config: two anchors, a hostname and a clock.
static uint8_t rxbuf[CH_MIN_RXBUF];
static const uint8_t anchor_der[] = {0x30, 0x00};
static ch_trust_anchor anchors[CH_WEBPKI_ANCHOR_MAX + 1];
static const uint8_t host[] = {'s', '3', '.', 'e', 'x', 'a', 'm', 'p',
                               'l', 'e', '.', 't', 'e', 's', 't'};

static ch_cfg valid_cfg(mock_server *s) {
    for (size_t i = 0; i < sizeof anchors / sizeof anchors[0]; i++) {
        anchors[i] =
            (ch_trust_anchor){anchor_der, sizeof anchor_der, anchor_der, sizeof anchor_der};
    }
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
#include "webpki_session_cases.h"

int main(void) {
    test_webpki_cfg_anchors();
    test_webpki_cfg_clock();
    test_webpki_cfg_hostname();
    test_webpki_cfg_other_modes();
    test_rxbuf_floor();
    test_webpki_hello();
    test_webpki_hello_boundary();
    test_webpki_handshake_fails_closed();
    if (failures > 0) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)printf("webpki_session_test: all checks passed\n");
    return 0;
}
