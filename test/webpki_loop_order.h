// The server's default cipher suite order, over a ClientHello that lists
// the three suites of RFC 9846 §9.1 in each of their six orders, through
// the real parser: srv_parse_client_hello, then srv_select with no
// ch_srv_cfg.cipher_suites. The server reads the offer as a set and
// selects by its own order (docs/decisions.md 80), so every order selects
// one suite: TLS_AES_256_GCM_SHA384 in a SUITE=aesgcm build on AES=hw
// that defines CH_NATIVE_AES, and TLS_CHACHA20_POLY1305_SHA256 in the
// AES=extern suite build and in a build without the suite, whose parser
// reads the two AES-GCM code points and passes over them
// (rfc9846.txt:1275-1278). test/webpki_loop_test.c includes this file in
// bin/webpki_loop_aes, bin/webpki_loop_aes_extern and
// bin/webpki_loop_tcp_nonblocking, and test/webpki_loop_suites.h builds
// h3spec's offer with offer_body.
#ifndef CH_TEST_WEBPKI_LOOP_ORDER_H
#define CH_TEST_WEBPKI_LOOP_ORDER_H

#include "srv_flight.h"
#include "srv_parser.h"

// The suite the server's default order selects from an offer of all
// three, read from the build's defines rather than from suite.h's
// SUITE_AES_FIRST, so a change to suite.h's rule shows here as a failure.
#if defined(CH_SUITE_AES_GCM) && defined(CH_AES_HW) && defined(CH_NATIVE_AES)
#define ORDER_DEFAULT_PICK SUITE_AES_256_GCM_SHA384
#else
#define ORDER_DEFAULT_PICK SUITE_CHACHA20_POLY1305_SHA256
#endif

// A ClientHello body that lists count cipher suites in the order given,
// over x25519 with one key share and one signature scheme this server
// signs. The body has no handshake header, as srv_parse_client_hello
// takes it.
static size_t offer_body(uint8_t *out, size_t cap, const uint8_t share[X25519_LEN],
                         const uint16_t *suites, size_t count) {
    wbuf w;
    wb_init(&w, out, cap);
    wb_u16(&w, 0x0303);
    for (int i = 0; i < 32; i++) {
        wb_u8(&w, (uint8_t)i);
    }
    wb_u8(&w, 0); // legacy_session_id
    wb_u16(&w, (uint16_t)(2 * count));
    for (size_t i = 0; i < count; i++) {
        wb_u16(&w, suites[i]);
    }
    wb_u8(&w, 1);
    wb_u8(&w, 0);
    size_t exts = wb_mark(&w, 2);
    wb_u16(&w, EXT_SUPPORTED_VERSIONS);
    wb_u16(&w, 3);
    wb_u8(&w, 2);
    wb_u16(&w, TLS13);
    wb_u16(&w, EXT_SUPPORTED_GROUPS);
    wb_u16(&w, 4);
    wb_u16(&w, 2);
    wb_u16(&w, CH_GROUP_X25519);
    wb_u16(&w, EXT_KEY_SHARE);
    wb_u16(&w, 2 + 4 + X25519_LEN);
    wb_u16(&w, 4 + X25519_LEN);
    wb_u16(&w, CH_GROUP_X25519);
    wb_u16(&w, X25519_LEN);
    wb_bytes(&w, share, X25519_LEN);
    wb_u16(&w, EXT_SIGNATURE_ALGORITHMS);
    wb_u16(&w, 4);
    wb_u16(&w, 2);
    wb_u16(&w, SIGALG_ECDSA_P256_SHA256);
    wb_patch16(&w, exts);
    return w.err ? 0 : w.len;
}

// srv_select over ch on a fresh session that names no suite order, so
// the server walks its default one.
static int select_by_default_order(const client_hello *ch, selection *sel) {
    static ch_tls t;
    handshake_state h;
    memset(&t, 0, sizeof t);
    server_config(&t.cfg, ticket_key);
    memset(&h, 0, sizeof h);
    h.t = &t;
    return srv_select(&h, ch, sel);
}

// The three suites in each of their six orders, for the rows here and
// test/webpki_loop_suites.h's.
static const uint16_t suite_orders[6][3] = {
    {SUITE_CHACHA20_POLY1305_SHA256, SUITE_AES_128_GCM_SHA256,       SUITE_AES_256_GCM_SHA384      },
    {SUITE_CHACHA20_POLY1305_SHA256, SUITE_AES_256_GCM_SHA384,       SUITE_AES_128_GCM_SHA256      },
    {SUITE_AES_128_GCM_SHA256,       SUITE_CHACHA20_POLY1305_SHA256, SUITE_AES_256_GCM_SHA384      },
    {SUITE_AES_128_GCM_SHA256,       SUITE_AES_256_GCM_SHA384,       SUITE_CHACHA20_POLY1305_SHA256},
    {SUITE_AES_256_GCM_SHA384,       SUITE_CHACHA20_POLY1305_SHA256, SUITE_AES_128_GCM_SHA256      },
    {SUITE_AES_256_GCM_SHA384,       SUITE_AES_128_GCM_SHA256,       SUITE_CHACHA20_POLY1305_SHA256},
};

// Each of the six orders of the three suites selects ORDER_DEFAULT_PICK
// at the hash its suite fixes.
static void check_offer_orders(void) {
    const uint8_t share[X25519_LEN] = {0x09};
    for (size_t i = 0; i < 6; i++) {
        uint8_t body[128];
        size_t n = offer_body(body, sizeof body, share, suite_orders[i], 3);
        CHECK(n > 0);
        client_hello ch;
        memset(&ch, 0, sizeof ch);
        uint8_t alert = 0;
        CHECK(srv_parse_client_hello(body, n, &ch, NULL, 0, &alert) == CH_OK);
        selection sel;
        CHECK(select_by_default_order(&ch, &sel) == CH_OK);
        CHECK(sel.suite == ORDER_DEFAULT_PICK);
        CHECK(sel.hash_len == suite_hash_len(ORDER_DEFAULT_PICK));
    }
}

#endif
