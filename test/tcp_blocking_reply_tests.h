// The tcp-blocking server's replies to the smallest ClientHello it
// accepts (INV-63). RFC 9846 §4.3 forbids an extension response the
// client did not ask for, except a HelloRetryRequest's cookie
// (rfc9846.txt:1582-1587), and a strict client aborts the handshake on
// one (https://github.com/c4milo/chapulin/issues/206).
//
// No client this tree builds sends this hello: each one sends
// record_size_limit, so a loop between chapulin's two roles cannot show
// an unrequested reply. The hello is written here instead. It carries
// supported_versions, signature_algorithms, supported_groups with x25519
// alone, and key_share, which RFC 9846 §9.2 requires of a hello without
// a PSK. The server offers "h2" through ALPN, so a reply that names a
// protocol to a hello that offered none shows. Included by
// test/tcp_blocking_loop_test.c, after its wire and its server
// configuration. It sends tcp_blocking_retry_tests.h's retry_share.
#ifndef CH_TEST_TCP_BLOCKING_REPLY_TESTS_H
#define CH_TEST_TCP_BLOCKING_REPLY_TESTS_H

#include "buf.h"
#include "srv_message.h"
#include "tcp_blocking_retry_tests.h"

// The extensions minimal_hello writes, as flags.
#define REPLY_VERSIONS 1U
#define REPLY_SHARE 2U

// The extension types a reply carries, as flags.
#define REPLY_EXT_VERSIONS 1U
#define REPLY_EXT_KEY_SHARE 2U
#define REPLY_EXT_COOKIE 4U
#define REPLY_EXT_OTHER 8U

static const uint8_t reply_alpn_h2[2] = {'h', '2'};
static const ch_alpn_protocol reply_alpn[1] = {
    {reply_alpn_h2, sizeof reply_alpn_h2}
};

// One plaintext ClientHello record with an empty legacy_session_id,
// ChaCha20, rsa_pss_rsae_sha256 and the x25519 group. supported_versions
// and the x25519 key share are each there when flags names them; the
// key_share extension is there either way, with an empty list when the
// share is not. Returns its length.
static size_t minimal_hello(uint8_t *out, size_t cap, unsigned flags) {
    wbuf w;
    wb_init(&w, out, cap);
    wb_u8(&w, REC_HANDSHAKE);
    wb_u16(&w, 0x0301);
    size_t rec = wb_mark(&w, 2);
    wb_u8(&w, HS_CLIENT_HELLO);
    size_t msg = wb_mark(&w, 3);
    wb_u16(&w, 0x0303);
    for (int i = 0; i < 32; i++) {
        wb_u8(&w, (uint8_t)(0x60 + i)); // random
    }
    wb_u8(&w, 0); // legacy_session_id
    wb_u16(&w, 2);
    wb_u16(&w, SUITE_CHACHA20_POLY1305_SHA256);
    wb_u8(&w, 1);
    wb_u8(&w, 0); // legacy_compression_methods
    size_t exts = wb_mark(&w, 2);
    if ((flags & REPLY_VERSIONS) != 0) {
        wb_u16(&w, EXT_SUPPORTED_VERSIONS);
        wb_u16(&w, 3);
        wb_u8(&w, 2);
        wb_u16(&w, TLS13);
    }
    wb_u16(&w, EXT_SIGNATURE_ALGORITHMS);
    wb_u16(&w, 4);
    wb_u16(&w, 2);
    wb_u16(&w, SIGALG_RSA_PSS_RSAE_SHA256);
    wb_u16(&w, EXT_SUPPORTED_GROUPS);
    wb_u16(&w, 4);
    wb_u16(&w, 2);
    wb_u16(&w, CH_GROUP_X25519);
    wb_u16(&w, EXT_KEY_SHARE);
    size_t ext = wb_mark(&w, 2);
    size_t list = wb_mark(&w, 2);
    if ((flags & REPLY_SHARE) != 0) {
        wb_u16(&w, CH_GROUP_X25519);
        wb_u16(&w, X25519_LEN);
        wb_bytes(&w, retry_share, X25519_LEN);
    }
    wb_patch16(&w, list);
    wb_patch16(&w, ext);
    wb_patch16(&w, exts);
    wb_patch24(&w, msg);
    wb_patch16(&w, rec);
    return w.err ? 0 : w.len;
}

// The extension types of the ServerHello or HelloRetryRequest record at
// the front of to_client, as REPLY_EXT_ flags, and the group its key_share
// names in *group. A key_share body is the group and then, in a
// ServerHello, the share; either way the group comes first.
static unsigned hello_reply_extensions(uint16_t *group) {
    rbuf r;
    rb_init(&r, to_client.bytes + REC_HDR, record_at(to_client.bytes, 0) - REC_HDR);
    rb_skip(&r, 4 + 2 + 32); // handshake header, legacy_version, random
    rb_skip(&r, rb_u8(&r));  // legacy_session_id_echo
    rb_skip(&r, 2 + 1 + 2);  // cipher_suite, compression, extensions length
    unsigned found = 0;
    *group = 0;
    while (rb_left(&r) > 0 && !r.err) {
        uint16_t type = rb_u16(&r);
        size_t ext_len = rb_u16(&r);
        const uint8_t *body = rb_bytes(&r, ext_len);
        if (type == EXT_SUPPORTED_VERSIONS) {
            found |= REPLY_EXT_VERSIONS;
        } else if (type == EXT_KEY_SHARE && body != NULL && ext_len >= 2) {
            found |= REPLY_EXT_KEY_SHARE;
            *group = (uint16_t)((body[0] << 8) | body[1]);
        } else if (type == EXT_COOKIE) {
            found |= REPLY_EXT_COOKIE;
        } else {
            found |= REPLY_EXT_OTHER;
        }
    }
    CHECK(!r.err);
    return found;
}

// ch_srv_accept over the hello flags names, with "h2" on the server's ALPN
// list. The recv callback has nothing more to give after the hello, so
// the server stops where it waits for the client's next message.
static int serve_minimal_hello(unsigned flags) {
    memset(&to_server, 0, sizeof to_server);
    memset(&to_client, 0, sizeof to_client);
    to_server.len = minimal_hello(to_server.bytes, sizeof to_server.bytes, flags);
    CHECK(to_server.len > 0);
    ch_cfg scfg;
    server_config(&scfg, read_to_server);
    scfg.alpn_protocols = reply_alpn;
    scfg.alpn_count = 1;
    static ch_tls server;
    return ch_srv_accept(&server, &scfg);
}

static void test_reply_extensions(void) {
    // The full flight to a hello with a share: a ServerHello with
    // supported_versions and an x25519 key_share alone, then an
    // EncryptedExtensions with an empty list. That message is a 4-byte
    // header and a 2-byte list length, sealed with its content type byte
    // and the tag, so its record length shows any extension in it.
    uint16_t group = 0;
    CHECK(serve_minimal_hello(REPLY_VERSIONS | REPLY_SHARE) == CH_EIO);
    CHECK(to_client.bytes[REC_HDR] == HS_SERVER_HELLO);
    CHECK(memcmp(to_client.bytes + REC_HDR + 6, srv_hrr_random, SRV_RANDOM) != 0);
    CHECK(hello_reply_extensions(&group) == (REPLY_EXT_VERSIONS | REPLY_EXT_KEY_SHARE));
    CHECK(group == CH_GROUP_X25519);
    size_t second = record_at(to_client.bytes, 0);
    CHECK(to_client.len > second + REC_HDR);
    CHECK(to_client.bytes[second] == REC_APPDATA);
    CHECK(record_at(to_client.bytes, second) == REC_OVERHEAD + 6);

    // A hello that lists x25519 and shares nothing: a HelloRetryRequest
    // with supported_versions, a key_share that names x25519, and the
    // cookie, the one extension §4.3 lets a server send unasked.
    CHECK(serve_minimal_hello(REPLY_VERSIONS) == CH_EIO);
    CHECK(to_client.bytes[REC_HDR] == HS_SERVER_HELLO);
    CHECK(memcmp(to_client.bytes + REC_HDR + 6, srv_hrr_random, SRV_RANDOM) == 0);
    CHECK(hello_reply_extensions(&group) ==
          (REPLY_EXT_VERSIONS | REPLY_EXT_KEY_SHARE | REPLY_EXT_COOKIE));
    CHECK(group == CH_GROUP_X25519);

    // A hello without supported_versions does not negotiate TLS 1.3, so
    // no reply may carry that extension: the answer is the
    // protocol_version alert in the clear, and nothing else
    // (rfc9846.txt:1306-1313).
    CHECK(serve_minimal_hello(REPLY_SHARE) == CH_EPROTO);
    const uint8_t alert[REC_HDR + 2] = {REC_ALERT, 0x03, 0x03, 0, 2, 2, ALERT_PROTOCOL_VERSION};
    CHECK(to_client.len == sizeof alert);
    CHECK(memcmp(to_client.bytes, alert, sizeof alert) == 0);
}

#endif
