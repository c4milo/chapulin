// The tcp-blocking server's HelloRetryRequest path under RFC 9846 §5.1
// (INV-39): the second ClientHello must end its record, because the read
// key changes after the ServerHello that answers it. The first one needs
// no such check, because the read key does not change between the two.
//
// The hellos are written here: no client this tree builds lists a group
// and sends no share for it (docs/decisions.md 63), so none draws a
// HelloRetryRequest from this server. The first hello lists x25519 and
// shares nothing; the second is the same hello with an x25519 share and
// the cookie the HelloRetryRequest carried, and it has retry_extra zero
// bytes after it in its record. Included by test/tcp_blocking_loop_test.c
// after its wire and its server configuration.
#ifndef CH_TEST_TCP_BLOCKING_RETRY_TESTS_H
#define CH_TEST_TCP_BLOCKING_RETRY_TESTS_H

#include "buf.h"
#include "x25519.h"

static uint8_t retry_share[X25519_LEN];
static size_t retry_extra;
static int retried;

// One plaintext ClientHello record offering ChaCha20, rsa_pss_rsae_sha256
// and x25519. With cookie NULL it is the first hello, with an empty
// key_share list; otherwise it is the second, with an x25519 share and a
// cookie extension carrying cookie_len bytes. Returns its length.
static size_t retry_hello(uint8_t *out, size_t cap, const uint8_t *cookie, size_t cookie_len) {
    wbuf w;
    wb_init(&w, out, cap);
    wb_u8(&w, REC_HANDSHAKE);
    wb_u16(&w, cookie == NULL ? 0x0301 : 0x0303);
    size_t rec = wb_mark(&w, 2);
    wb_u8(&w, HS_CLIENT_HELLO);
    size_t msg = wb_mark(&w, 3);
    wb_u16(&w, 0x0303);
    for (int i = 0; i < 32; i++) {
        wb_u8(&w, (uint8_t)(0x90 + i)); // random, the same in both hellos
    }
    wb_u8(&w, 0); // legacy_session_id
    wb_u16(&w, 2);
    wb_u16(&w, SUITE_CHACHA20_POLY1305_SHA256);
    wb_u8(&w, 1);
    wb_u8(&w, 0); // legacy_compression_methods
    size_t exts = wb_mark(&w, 2);
    wb_u16(&w, EXT_SUPPORTED_VERSIONS);
    wb_u16(&w, 3);
    wb_u8(&w, 2);
    wb_u16(&w, TLS13);
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
    if (cookie != NULL) {
        wb_u16(&w, CH_GROUP_X25519);
        wb_u16(&w, X25519_LEN);
        wb_bytes(&w, retry_share, X25519_LEN);
    }
    wb_patch16(&w, list);
    wb_patch16(&w, ext);
    if (cookie != NULL) {
        wb_u16(&w, EXT_COOKIE);
        wb_u16(&w, (uint16_t)cookie_len);
        wb_bytes(&w, cookie, cookie_len);
    }
    wb_patch16(&w, exts);
    wb_patch24(&w, msg);
    wb_patch16(&w, rec);
    return w.err ? 0 : w.len;
}

// The body of the cookie extension of the HelloRetryRequest at the front
// of to_client, which the second hello echoes whole, or NULL when it
// carries none.
static const uint8_t *retry_cookie(size_t *len) {
    rbuf r;
    rb_init(&r, to_client.bytes + REC_HDR, record_at(to_client.bytes, 0) - REC_HDR);
    rb_skip(&r, 4 + 2 + 32); // handshake header, legacy_version, random
    rb_skip(&r, rb_u8(&r));  // legacy_session_id_echo
    rb_skip(&r, 2 + 1 + 2);  // cipher_suite, compression, extensions length
    while (rb_left(&r) > 0 && !r.err) {
        uint16_t type = rb_u16(&r);
        size_t ext_len = rb_u16(&r);
        const uint8_t *body = rb_bytes(&r, ext_len);
        if (type == EXT_COOKIE && body != NULL) {
            *len = ext_len;
            return body;
        }
    }
    return NULL;
}

// The server's recv. The first time it finds nothing to read, which is
// when it waits for the second hello, the second hello goes in.
static int retry_recv(void *io, uint8_t *p, size_t n) {
    if (to_server.off == to_server.len && !retried) {
        retried = 1;
        size_t cookie_len = 0;
        const uint8_t *cookie = retry_cookie(&cookie_len);
        CHECK(cookie != NULL);
        uint8_t *at = to_server.bytes + to_server.len;
        size_t len = retry_hello(at, WIRE_MAX - to_server.len, cookie, cookie_len);
        CHECK(len > 0);
        grow_first_record(at, &len, WIRE_MAX - to_server.len, retry_extra);
        to_server.len += len;
    }
    return read_to_server(io, p, n);
}

// ch_srv_accept over a HelloRetryRequest round whose second hello has
// bytes zero bytes after it in its record.
static void server_reads_retry_hello(size_t bytes) {
    memset(&to_server, 0, sizeof to_server);
    memset(&to_client, 0, sizeof to_client);
    retried = 0;
    retry_extra = bytes;
    to_server.len = retry_hello(to_server.bytes, sizeof to_server.bytes, NULL, 0);
    CHECK(to_server.len > 0);
    ch_cfg scfg;
    server_config(&scfg, retry_recv);
    static ch_tls server;
    int rc = ch_srv_accept(&server, &scfg);
    CHECK(retried == 1);
    size_t second = record_at(to_client.bytes, 0);
    if (bytes == 0) {
        // The ServerHello followed the HelloRetryRequest, and the server
        // then waited for a client Finished this case never sends.
        CHECK(rc == CH_EIO && to_client.len > second + REC_HDR);
        CHECK(to_client.bytes[second] == REC_HANDSHAKE);
        CHECK(to_client.bytes[second + REC_HDR] == HS_SERVER_HELLO);
        return;
    }
    // Refused before the ServerHello: the alert, in the clear, is all that
    // followed the HelloRetryRequest.
    CHECK(rc == CH_EPROTO && server.state == CH_ST_FAILED);
    const uint8_t alert[REC_HDR + 2] = {REC_ALERT, 0x03, 0x03, 0, 2, 2, ALERT_UNEXPECTED_MESSAGE};
    CHECK(to_client.len == second + sizeof alert);
    CHECK(memcmp(to_client.bytes + second, alert, sizeof alert) == 0);
}

#endif
