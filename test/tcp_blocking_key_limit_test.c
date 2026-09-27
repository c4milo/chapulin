// The AES-GCM key-usage ceiling over TRANSPORT=tcp-blocking: this tree's
// TRUST=webpki client, through ch_connect, against this tree's server, both
// from the ROLE=both TRUST=webpki SUITE=aesgcm object's sources, on
// AES=extern so every host runs it (docs/decisions.md 78).
//
// A blocking driver waits inside its recv callback for the peer's next
// flight, so two blocking drivers in one thread would each wait for the
// other. The server here is the test's own calls to the flight handlers
// srv_handshake.c calls, in its order, made from inside the client's recv,
// as bin/tcp_blocking_loop_test drives them. Once ch_connect returns, the
// server reads the client Finished and srv_complete installs its read key,
// so each end holds the session its blocking driver would leave. The
// server presents the r2 corpus chain and signs with its leaf key
// (test/webpki_r2_chain.h), so the client runs the whole chain walk.
// test/key_limit_cases.h then writes across the ceiling both ways.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "ct.h"
#include "handshake_message.h"
#include "handshake_record.h"
#include "rand.h"
#include "record.h"
#include "srv_flight.h"
#include "tls.h"

#if !defined(CH_SUITE_AES_GCM) || !defined(CH_ROLE_BOTH) || !defined(CH_TRUST_WEBPKI)
#error "the key limit loop needs the ROLE=both TRUST=webpki SUITE=aesgcm defines"
#endif

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// A counter, not entropy. Both roles draw from it, so the two key shares
// differ and a failure replays exactly.
void ch_rand_bytes(uint8_t *p, size_t n) {
    static uint8_t counter = 1;
    for (size_t i = 0; i < n; i++) {
        p[i] = counter++;
    }
}

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

#include "webpki_r2_chain.h"

// One direction of the handshake: the bytes one end sent and how many of
// them the other end has read. The server's flight, the hybrid
// ServerHello and a Certificate of 1037 bytes among it, is under 4 KiB.
typedef struct {
    uint8_t bytes[8192];
    size_t len;
    size_t off;
} wire;
static wire to_server;
static wire to_client;

static int put(wire *w, const uint8_t *p, size_t n) {
    if (w->len + n > sizeof w->bytes) {
        return -1;
    }
    memcpy(w->bytes + w->len, p, n);
    w->len += n;
    return 0;
}

// Hands over what was sent and not yet read, and -1 once nothing is left,
// which a blocking driver takes as the end of the connection.
static int take(wire *w, uint8_t *p, size_t n) {
    size_t left = w->len - w->off;
    if (left == 0) {
        return -1;
    }
    size_t count = n < left ? n : left;
    memcpy(p, w->bytes + w->off, count);
    w->off += count;
    return (int)count;
}

static int send_to_server(void *io, const uint8_t *p, size_t n) {
    (void)io;
    return put(&to_server, p, n);
}

static int send_to_client(void *io, const uint8_t *p, size_t n) {
    (void)io;
    return put(&to_client, p, n);
}

static int read_to_server(void *io, uint8_t *p, size_t n) {
    (void)io;
    return take(&to_server, p, n);
}

static const uint8_t cookie_key[SHA256_LEN] = {7};
static uint8_t srv_buf[CH_MIN_RXBUF];
static uint8_t cli_buf[CH_MIN_RXBUF];

// The server's session and handshake state, the one suite its order names,
// and whether its flight has gone out.
static ch_tls srv_t;
static handshake_state srv_h;
static uint16_t srv_order[1];
static int served;

// The server's flight up to its Finished, as srv_handshake.c's
// hello_exchange and auth_flight send it for a hello that needs no
// HelloRetryRequest. The client's session id is empty, so no dummy
// change_cipher_spec is owed.
static int serve_flight(void) {
    client_hello ch;
    selection sel;
    memset(&ch, 0, sizeof ch);
    memset(&sel, 0, sizeof sel);
    srv_begin(&srv_h);
    int rc = srv_read_client_hello(&srv_h, &ch);
    if (rc == CH_OK) {
        rc = srv_select(&srv_h, &ch, &sel);
    }
    if (rc == CH_OK && sel.need_retry != 0) {
        rc = CH_EPROTO; // the client shares the hybrid, which the server takes
    }
    if (rc == CH_OK) {
        rc = srv_send_server_hello(&srv_h, &ch, &sel);
    }
    if (rc != CH_OK) {
        return rc;
    }
    srv_store_selection(&srv_t, &ch, &sel);
    rc = srv_derive_handshake_secrets(&srv_h, &ch, &sel);
    if (rc == CH_OK) {
        rc = srv_send_encrypted_extensions(&srv_h, &sel);
    }
    if (rc == CH_OK) {
        rc = srv_send_certificate(&srv_h, &sel);
    }
    if (rc == CH_OK) {
        rc = srv_send_certificate_verify(&srv_h, &sel);
    }
    return rc == CH_OK ? srv_send_finished(&srv_h) : rc;
}

// The client's recv. The first time it finds nothing to read, the server
// answers the ClientHello.
static int client_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    if (to_client.off == to_client.len && !served) {
        served = 1;
        if (serve_flight() != CH_OK) {
            return -1;
        }
    }
    return take(&to_client, p, n);
}

// The server's session and handshake state, set up as ch_srv_accept and
// srv_handshake set up their own before the first handler runs, with the
// r2 identity and an order that names suite alone.
static void server_start(uint16_t suite) {
    memset(&srv_t, 0, sizeof srv_t);
    memset(&srv_h, 0, sizeof srv_h);
    srv_t.cfg.buf = srv_buf;
    srv_t.cfg.buf_len = sizeof srv_buf;
    srv_t.cfg.send = send_to_client;
    srv_t.cfg.recv = read_to_server;
    srv_t.cfg.srv.cookie_key = cookie_key;
    srv_order[0] = suite;
    srv_t.cfg.srv.cipher_suites = srv_order;
    srv_t.cfg.srv.cipher_suite_count = 1;
    CHECK(r2_identity(&srv_t.cfg.srv.ecdsa_p256));
    srv_t.server = 1;
    srv_t.peer_limit = CH_TX_PT;
    srv_t.alpn_selected = CH_ALPN_NONE;
    srv_h.t = &srv_t;
    srv_h.alert = ALERT_DECODE_ERROR;
    size_t room = srv_t.cfg.buf_len - REC_HDR - AEAD_TAG;
    srv_h.record_size_limit = room > 0x4001 ? 0x4001 : (uint16_t)room;
}

static ch_tls client;

// One handshake whose ServerHello selects suite, for
// test/key_limit_cases.h: ch_connect, then the server's read of the client
// Finished and srv_complete, which srv_handshake.c's auth_flight and run
// end with. The server sends no ticket, so nothing waits on either wire.
static int key_limit_connect(uint16_t suite, ch_tls **client_out, ch_tls **server_out) {
    memset(&to_server, 0, sizeof to_server);
    memset(&to_client, 0, sizeof to_client);
    served = 0;
    server_start(suite);
    ch_cfg ccfg;
    memset(&ccfg, 0, sizeof ccfg);
    ccfg.buf = cli_buf;
    ccfg.buf_len = sizeof cli_buf;
    ccfg.send = send_to_server;
    ccfg.recv = client_recv;
    r2_trust(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test");
    if (ch_connect(&client, &ccfg) != CH_OK) {
        return 0;
    }
    if (srv_read_client_finished(&srv_h) != CH_OK || hsr_check_record_end(&srv_h) != CH_OK) {
        return 0;
    }
    srv_complete(&srv_h);
    ct_wipe(&srv_h, sizeof srv_h);
    if (client.suite != suite || srv_t.suite != suite || srv_t.state != CH_ST_CONNECTED) {
        return 0;
    }
    *client_out = &client;
    *server_out = &srv_t;
    return 1;
}

#include "key_limit_cases.h"

int main(void) {
    // webpki_r2_chain.h's large-leaf helpers serve the pins-alone rows of
    // the other loops; this one presents the r2 chain alone.
    (void)r2_large_identity;
    (void)r2_large_pin;
    check_key_limit();
    if (failures == 0) {
        (void)printf("tcp_blocking_key_limit: under AES-128-GCM and AES-256-GCM each end sent one"
                     " KeyUpdate at its write key's last sequence number and the other read on"
                     " across it, the sender cap failed the write with internal_error, and"
                     " ChaCha20 sent none\n");
        return 0;
    }
    (void)fprintf(stderr, "tcp_blocking_key_limit: %d failures\n", failures);
    return 1;
}
