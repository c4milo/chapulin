// Each tcp-blocking driver against the other role's flight handlers, in
// one process: ch_connect (handshake.c) against srv_flight.h's handlers,
// and ch_srv_accept (srv_handshake.c) against handshake_flight.h's. A
// blocking driver waits inside its recv callback for the peer's next
// flight, so two blocking drivers in one thread would each wait for the
// other. Here the peer is the test's own calls to its handlers, made from
// inside the driver's recv callback in the order srv_handshake.c and
// handshake.c make them. The Makefile builds it from the ROLE=both
// TRANSPORT=tcp-blocking sources, the one object that carries both
// blocking drivers.
//
// It exists for RFC 9846 §5.1 (INV-39): the message before a key change
// must end its record, and one that does not ends the connection with
// unexpected_message (rfc9846.txt:3464-3470). Each case adds bytes after
// one such message in its record: the ServerHello and the server
// Finished the client reads, the ClientHello and the client Finished the
// server reads, and the second ClientHello of a HelloRetryRequest round
// (test/tcp_blocking_retry_tests.h). Each runs twice: with 0 bytes added
// the driver must go on, which shows the edit itself is sound, and with 1
// it must refuse. bin/tcp_nonblocking_loop_test holds the tcp-nonblocking
// drivers to the same rule.
//
// The auth mode is the pinned one, as in bin/tcp_nonblocking_loop_test:
// the client pins the server's provisioned RSA modulus, and pinned mode
// hashes the certificate into the transcript without reading it.
//
// bin/tcp_blocking_loop_session is the same main under -DCH_RAND_SESSION:
// every session draws from the source its ch_cfg names, and
// test/tcp_blocking_session_tests.h checks what each source handed out.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "handshake_auth.h"
#include "handshake_flight.h"
#include "handshake_message.h"
#include "rand.h"
#include "record.h"
#include "rsa_sign.h"
#include "rsa_sign_vectors.h"
#include "srv.h"
#include "srv_flight.h"
#include "tls.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#ifdef CH_RAND_SESSION
#include "rand_session.h"
#else
// A counter, not entropy. Both roles draw from it, so the two key shares
// differ and a failure replays exactly.
void ch_rand_bytes(uint8_t *p, size_t n) {
    static uint8_t counter = 1;
    for (size_t i = 0; i < n; i++) {
        p[i] = counter++;
    }
}
#endif

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

#include "record_edit.h"

// One direction of the connection: the bytes one end sent and how many
// of them the other end has read.
#define WIRE_MAX 8192
typedef struct {
    uint8_t bytes[WIRE_MAX];
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

// Hands over what was sent and not yet read, and -1 once nothing is
// left, which a blocking driver takes as the end of the connection.
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

static int read_to_client(void *io, uint8_t *p, size_t n) {
    (void)io;
    return take(&to_client, p, n);
}

// One certificate the chain pointer names, in the shape
// bin/tcp_nonblocking_loop_test uses: valid DER that nothing here parses.
static const uint8_t cert_der[4] = {0x30, 0x02, 0x05, 0x00};
static const ch_cert chain[1] = {
    {cert_der, sizeof cert_der}
};
static const uint8_t cookie_key[SHA256_LEN] = {7};
static ch_rsa_priv rsa_key;
static uint8_t srv_buf[CH_MIN_RXBUF];
static uint8_t cli_buf[CH_MIN_RXBUF];

typedef int (*recv_fn)(void *io, uint8_t *p, size_t n);

// The rsa_pss identity alone, because the client pins its modulus.
static void server_config(ch_cfg *cfg, recv_fn recv) {
    memset(cfg, 0, sizeof *cfg);
    cfg->buf = srv_buf;
    cfg->buf_len = sizeof srv_buf;
    cfg->send = send_to_client;
    cfg->recv = recv;
    cfg->srv.cookie_key = cookie_key;
    memset(&rsa_key, 0, sizeof rsa_key);
    rsa_key.n_len = sizeof rsa_sign_2048_n;
    memcpy(rsa_key.n, rsa_sign_2048_n, sizeof rsa_sign_2048_n);
    memcpy(rsa_key.d, rsa_sign_2048_d, sizeof rsa_sign_2048_d);
    cfg->srv.rsa_pss.chain = chain;
    cfg->srv.rsa_pss.chain_count = 1;
    cfg->srv.rsa_pss.priv = &rsa_key;
    cfg->srv.rsa_pss.priv_len = sizeof rsa_key;
    cfg->srv.rsa_pss.pub = rsa_sign_2048_n;
    cfg->srv.rsa_pss.pub_len = sizeof rsa_sign_2048_n;
#ifdef CH_RAND_SESSION
    attach_source(cfg, &server_source);
#endif
}

static void client_config(ch_cfg *cfg, recv_fn recv) {
    memset(cfg, 0, sizeof *cfg);
    cfg->buf = cli_buf;
    cfg->buf_len = sizeof cli_buf;
    cfg->send = send_to_server;
    cfg->recv = recv;
    cfg->server_pubkey = rsa_sign_2048_n;
    cfg->server_pubkey_len = sizeof rsa_sign_2048_n;
#ifdef CH_RAND_SESSION
    attach_source(cfg, &client_source);
#endif
}

// The record_size_limit each driver sizes to its buffer, the arithmetic
// ch_handshake and srv_handshake do.
static uint16_t own_record_size_limit(size_t buf_len) {
    size_t room = buf_len - REC_HDR - AEAD_TAG;
    return room > 0x4001 ? 0x4001 : (uint16_t)room;
}

// A session and handshake state set up as the blocking driver of that
// role sets up its own before the first handler runs.
static void peer_state(ch_tls *t, handshake_state *h, const ch_cfg *cfg) {
    memset(t, 0, sizeof *t);
    memset(h, 0, sizeof *h);
    t->cfg = *cfg;
    t->peer_limit = CH_TX_PT;
    t->alpn_selected = CH_ALPN_NONE;
    h->t = t;
    h->alert = ALERT_DECODE_ERROR;
    h->record_size_limit = own_record_size_limit(cfg->buf_len);
}

// ch_connect against the server's handlers. The server's session and
// state, which record of its flight gets flight_extra zero bytes added,
// and whether the flight has gone out.
static ch_tls srv_t;
static handshake_state srv_h;
static int edit_finished;
static size_t flight_extra;
static int served;

// The server's flight up to its Finished, as srv_handshake.c's
// hello_exchange and auth_flight send it for a hello that needs no
// HelloRetryRequest.
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
        rc = CH_EPROTO; // every hello here carries a share the server takes
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
// answers the ClientHello, and the test adds flight_extra zero bytes after
// the ServerHello or after the server Finished in its record.
static int client_recv(void *io, uint8_t *p, size_t n) {
    if (to_client.off == to_client.len && !served) {
        served = 1;
        if (serve_flight() != CH_OK) {
            return -1;
        }
        if (edit_finished) {
            reseal_last_record(to_client.bytes, &to_client.len, WIRE_MAX, srv_h.s_hs, flight_extra);
        } else {
            grow_first_record(to_client.bytes, &to_client.len, WIRE_MAX, flight_extra);
        }
    }
    return read_to_client(io, p, n);
}

// The alert the client sent last: in the clear before its handshake keys,
// and under its handshake write key once it has them.
static void check_client_alert(int keyed) {
    const uint8_t *rec = to_server.bytes + to_server.off;
    size_t len = to_server.len - to_server.off;
    uint8_t pt[16];
    size_t pt_len = 0;
    uint8_t type = rec[0];
    if (keyed) {
        rec_dir reader;
        rec_dir_init(&reader, srv_h.c_hs);
        CHECK(rec_open(&reader, rec, len, pt, sizeof pt, &pt_len, &type) == 0);
    } else {
        CHECK(len == REC_HDR + 2);
        memcpy(pt, rec + REC_HDR, 2);
        pt_len = 2;
    }
    CHECK(type == REC_ALERT && pt_len == 2 && pt[0] == 2 && pt[1] == ALERT_UNEXPECTED_MESSAGE);
}

// The client reads the ServerHello and, after its key change, the server
// Finished. The one after_finished names has bytes zero bytes after it in
// its record.
static void client_reads_flight(int after_finished, size_t bytes) {
    memset(&to_server, 0, sizeof to_server);
    memset(&to_client, 0, sizeof to_client);
    ch_cfg scfg;
    server_config(&scfg, read_to_server);
    peer_state(&srv_t, &srv_h, &scfg);
    edit_finished = after_finished;
    flight_extra = bytes;
    served = 0;
    ch_cfg ccfg;
    client_config(&ccfg, client_recv);
    static ch_tls client;
    int rc = ch_connect(&client, &ccfg);
    if (bytes == 0) {
        CHECK(rc == CH_OK && client.state == CH_ST_CONNECTED);
        // The server verifies the Finished the client answered with.
        CHECK(srv_read_client_finished(&srv_h) == CH_OK);
        return;
    }
    CHECK(rc == CH_EPROTO && client.state == CH_ST_FAILED);
    CHECK(ch_alert_sent(&client) == ALERT_UNEXPECTED_MESSAGE && ch_alert_received(&client) == 0);
    check_client_alert(after_finished);
}

// ch_srv_accept against the client's handlers. The client's session and
// state, the bytes after its Finished, and whether it has answered.
static ch_tls cli_t;
static handshake_state cli_h;
static size_t finished_extra;
static int answered;

// The ClientHello, as ch_handshake and send_client_hello write it, with
// bytes zero bytes after it in its record.
static void queue_client_hello(size_t bytes) {
    ch_cfg ccfg;
    client_config(&ccfg, read_to_client);
    peer_state(&cli_t, &cli_h, &ccfg);
    hsf_begin(&cli_h);
    size_t n = hsf_build_client_hello(&cli_h, cli_t.tx + REC_HDR, sizeof cli_t.tx - REC_HDR);
    CHECK(n > 0);
    cli_t.tx[0] = REC_HANDSHAKE;
    cli_t.tx[1] = 0x03;
    cli_t.tx[2] = 0x01;
    cli_t.tx[3] = (uint8_t)(n >> 8);
    cli_t.tx[4] = (uint8_t)n;
    CHECK(put(&to_server, cli_t.tx, REC_HDR + n) == 0);
    grow_first_record(to_server.bytes, &to_server.len, WIRE_MAX, bytes);
}

// The rest of the client's side, as handshake.c's run reads the server's
// flight and answers it, with finished_extra bytes after its Finished.
static int answer_flight(void) {
    server_hello_info info;
    int rc = hsf_read_server_hello(&cli_h, &info);
    if (rc == CH_OK) {
        rc = hsf_accept_server_hello(&cli_h, &info);
    }
    if (rc == CH_OK) {
        rc = hsf_derive_handshake_secrets(&cli_h, &info);
    }
    if (rc != CH_OK) {
        return rc;
    }
    rec_dir_init(&cli_t.rd, cli_h.s_hs);
    rec_dir_init(&cli_t.wr, cli_h.c_hs);
    cli_h.encrypted = 1;
    cli_t.keys = 1;
    rc = hsf_read_encrypted_extensions(&cli_h);
    if (rc == CH_OK) {
        rc = hsa_server_auth(&cli_h);
    }
    if (rc == CH_OK) {
        rc = hsf_read_finished(&cli_h);
    }
    if (rc != CH_OK) {
        return rc;
    }
    uint8_t finished[HSF_FINISHED_MAX + 1] = {0};
    size_t n = hsf_complete(&cli_h, finished);
    size_t out_len = 0;
    if (rec_seal(&cli_t.wr, REC_HANDSHAKE, finished, n + finished_extra, cli_t.tx, sizeof cli_t.tx,
                 &out_len) != 0) {
        return CH_ECAP;
    }
    return put(&to_server, cli_t.tx, out_len) == 0 ? CH_OK : CH_EIO;
}

// The server's recv. The first time it finds nothing to read, which is
// when it waits for the client Finished, the client answers the flight.
static int server_recv(void *io, uint8_t *p, size_t n) {
    if (to_server.off == to_server.len && !answered) {
        answered = 1;
        if (answer_flight() != CH_OK) {
            return -1;
        }
    }
    return read_to_server(io, p, n);
}

// The server reads the ClientHello and, after its key change, the client
// Finished. The one after_finished names has bytes zero bytes after it in
// its record.
static void server_reads_client(int after_finished, size_t bytes) {
    memset(&to_server, 0, sizeof to_server);
    memset(&to_client, 0, sizeof to_client);
    answered = 0;
    finished_extra = after_finished ? bytes : 0;
    queue_client_hello(after_finished ? 0 : bytes);
    ch_cfg scfg;
    server_config(&scfg, server_recv);
    static ch_tls server;
    int rc = ch_srv_accept(&server, &scfg);
    if (bytes == 0) {
        CHECK(rc == CH_OK && server.state == CH_ST_CONNECTED);
        return;
    }
    CHECK(rc == CH_EPROTO && server.state == CH_ST_FAILED);
    CHECK(ch_alert_sent(&server) == ALERT_UNEXPECTED_MESSAGE && ch_alert_received(&server) == 0);
    if (!after_finished) {
        // Refused before any ServerHello: the alert, in the clear, is all
        // that went out.
        const uint8_t alert[REC_HDR + 2] = {
            REC_ALERT, 0x03, 0x03, 0, 2, 2, ALERT_UNEXPECTED_MESSAGE};
        CHECK(to_client.len == sizeof alert && memcmp(to_client.bytes, alert, sizeof alert) == 0);
        return;
    }
    // After its Finished the server writes under its application key,
    // which the client holds as its read secret. The alert is the first
    // record under it.
    size_t len = to_client.len;
    size_t off = 0;
    while (off + record_at(to_client.bytes, off) < len) {
        off += record_at(to_client.bytes, off);
    }
    rec_dir reader;
    rec_dir_init(&reader, cli_t.rd_secret);
    uint8_t pt[16];
    size_t pt_len = 0;
    uint8_t type = 0;
    CHECK(rec_open(&reader, to_client.bytes + off, len - off, pt, sizeof pt, &pt_len, &type) == 0);
    CHECK(type == REC_ALERT && pt_len == 2 && pt[0] == 2 && pt[1] == ALERT_UNEXPECTED_MESSAGE);
}

#include "tcp_blocking_alert_tests.h"
#include "tcp_blocking_retry_tests.h"
#ifdef CH_RAND_SESSION
#include "tcp_blocking_session_tests.h"
#endif

int main(void) {
    static const uint8_t retry_scalar[X25519_LEN] = {0x2a};
    x25519_base(retry_share, retry_scalar);
    for (size_t bytes = 0; bytes <= 1; bytes++) {
        client_reads_flight(0, bytes);
        client_reads_flight(1, bytes);
        server_reads_client(0, bytes);
        server_reads_client(1, bytes);
        server_reads_retry_hello(bytes);
    }
    test_handshake_alerts();
#ifdef CH_RAND_SESSION
    test_session();
#endif
    if (failures == 0) {
        (void)printf("tcp_blocking_loop: ch_connect and ch_srv_accept each go on when the"
                     " message before a key change ends its record, a retried ClientHello"
                     " included, and refuse one byte after it with unexpected_message; each"
                     " reads the peer's fatal alert, in the clear or protected, and sends"
                     " nothing after it, and answers a 3-byte alert with decode_error; the"
                     " server refuses a client's NewSessionTicket\n");
        return 0;
    }
    (void)fprintf(stderr, "tcp_blocking_loop: %d failures\n", failures);
    return 1;
}
