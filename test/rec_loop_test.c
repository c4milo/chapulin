// Both tcp-nonblocking drivers against each other in one process: this
// tree's client (rec.c) and this tree's server (srv_rec.c) complete a
// whole TLS 1.3 handshake with no socket under either of them. The
// Makefile builds it as bin/rec_loop_test from the ROLE=both
// TRANSPORT=tcp-nonblocking source list, which is the one object that carries
// both drivers.
//
// Why it exists: INV-28 says a tcp-nonblocking build calls neither cfg.send
// nor cfg.recv while the handshake runs, and the server half was the
// only half measured. bin/srv_rec_test counts I/O calls on the server,
// and the client's only driver was bin/recclient, which needs a live
// server and so runs in check-slow. A claim checked once a night is
// checked rarely. Here both halves supply a send and a recv that count,
// and the test fails if either driver reaches for a socket.
//
// It answers a second question nothing else asks: whether the two
// drivers agree. bin/srv_rec_test feeds the server a ClientHello this
// tree builds at the message level and reads the records back; it never
// hands them to a client. This runs the client's own state machine over
// them, so a server flight the client refuses fails here rather than in
// an interop run.
//
// The auth mode is the pinned one, which is what lets the two meet with
// no certificate authority in the picture: the client pins the server's
// provisioned RSA modulus, and pinned mode hashes the certificate into
// the transcript without reading it (docs/server.md, "What the mode does
// not check"). So the chain below is four bytes of valid DER that no
// line of either side parses.
//
// It is built with the EXPORTER axis, because a connected pair is the
// only place the exporter's two derivation sites, handshake_flight.c's
// and srv_flight.c's, both run over one real transcript: after the
// handshake each side calls ch_export and the two answers must be one.
// bin/exporter_test checks the arithmetic against fixed vectors; this
// checks that the sessions derived the secret those vectors assume.
//
// It is built with the KEYLOG axis for the same reason. Each end hands
// every traffic secret to ch_keylog below, and the four labels must
// carry one client random and one secret apiece on both ends, which is
// what lets a capture tool decrypt a connection from either side's log.
//
// The Makefile builds it twice, once per group a raw client can offer.
// bin/rec_loop_test's client offers x25519 alone, and the server, which
// holds both groups, must select x25519. bin/rec_loop_pq's client is the
// KEX=pq one and offers X25519MLKEM768 alone, and the server must select
// the hybrid, for the full handshake and for the resumed one.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "handshake_message.h"
#include "keylog.h"
#include "rand.h"
#include "rec.h"
#include "record.h"
#include "rsa_sign.h"
#include "rsa_sign_vectors.h"
#include "srv_rec.h"
#include "tls.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// A counter, not entropy. Both halves draw from it, so the two key
// shares differ and a failure replays exactly.
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

// INV-28, both halves. Neither driver may call either of these while the
// handshake runs; they are required at configuration time because
// ch_read and ch_write call them once the session is connected.
static size_t io_calls;

// Set while the wrong-pin scenario runs, so the refusal it wants does
// not print a line that reads like a failure in check's output. A
// refusal outside that scenario still prints, because there it is one.
static int expect_refusal;

static int never_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    io_calls++;
    return -1;
}

// It poisons the buffer as well as counting, so a driver that read the
// socket cannot still look like it worked.
static int never_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    memset(p, 0xEE, n);
    io_calls++;
    return -1;
}

// One certificate the chain pointer names, in the shape bin/srv_rec_test
// uses: valid DER that nothing here parses.
static const uint8_t cert_der[4] = {0x30, 0x02, 0x05, 0x00};
static const ch_cert chain[1] = {
    {cert_der, sizeof cert_der}
};
static const uint8_t cookie_key[SHA256_LEN] = {7};

// The group both ends must report, the one the client's build offers.
#ifdef CH_KEX_PQ
#define LOOP_GROUP CH_GROUP_X25519MLKEM768
#else
#define LOOP_GROUP CH_GROUP_X25519
#endif

// The client's buffer is its build's floor, which sizes it for the
// ServerHello it reads. The server's holds the client's hello, and a
// KEX=pq client's carries the 1216-byte hybrid share and a ticket past
// that floor, so that build gives the server room for the largest hello
// its client sends.
#ifdef CH_KEX_PQ
#define LOOP_SRV_BUF (REC_HDR + CH_HELLO_MAX)
#else
#define LOOP_SRV_BUF CH_MIN_RXBUF
#endif
static uint8_t srv_buf[LOOP_SRV_BUF];
static uint8_t cli_buf[CH_MIN_RXBUF];
static ch_rsa_priv rsa_key;

// What the server pushed, waiting for the client to read it. One flight
// of five records fits: bin/srv_rec_test measures it at 512 bytes.
#define WIRE_MAX 4096
static struct {
    uint8_t bytes[WIRE_MAX];
    size_t len;
} to_client;

// How many records the server has pushed since run_handshake started, one
// per sink call, which is how the resumption cases count the flight.
static size_t records_pushed;

static int sink(void *io, const uint8_t *p, size_t n) {
    (void)io;
    if (to_client.len + n > sizeof to_client.bytes) {
        return -1;
    }
    memcpy(to_client.bytes + to_client.len, p, n);
    to_client.len += n;
    records_pushed++;
    return 0;
}

// What ch_keylog was handed, one row per call. The two sessions' cfg.io
// point at these two counters, so a row says which end logged it, and
// the hook writes through io the way a caller's file handle would: each
// counter ends at the number of lines its end logged.
static int client_io;
static int server_io;
#define LOG_MAX 16
static struct {
    int from_server;
    const char *label;
    uint8_t random[CH_KEYLOG_RANDOM_LEN];
    uint8_t secret[SHA256_LEN];
    size_t secret_len;
} logged[LOG_MAX];
static size_t logged_count;

void ch_keylog(void *io, const char *label, const uint8_t client_random[CH_KEYLOG_RANDOM_LEN],
               const uint8_t *secret, size_t secret_len) {
    CHECK(io == &client_io || io == &server_io);
    (*(int *)io)++;
    CHECK(logged_count < LOG_MAX);
    if (logged_count >= LOG_MAX) {
        return;
    }
    logged[logged_count].from_server = io == &server_io;
    logged[logged_count].label = label;
    memcpy(logged[logged_count].random, client_random, CH_KEYLOG_RANDOM_LEN);
    // Every suite this loop runs hashes with SHA-256.
    CHECK(secret_len == SHA256_LEN);
    memcpy(logged[logged_count].secret, secret, SHA256_LEN);
    logged[logged_count].secret_len = secret_len;
    logged_count++;
}

// The row one end logged under label, or NULL when it logged none. A
// second row under one label from one end is a failure of its own.
static const uint8_t *logged_secret(int from_server, const char *label, const uint8_t **random) {
    const uint8_t *found = NULL;
    for (size_t i = 0; i < logged_count; i++) {
        if (logged[i].from_server == from_server && strcmp(logged[i].label, label) == 0) {
            CHECK(found == NULL);
            found = logged[i].secret;
            *random = logged[i].random;
        }
    }
    return found;
}

// Every label logged once by each end, with one client random and one
// secret across the two ends, and no secret that is all zero.
static void check_logs_agree(void) {
    static const char *const labels[4] = {CH_KEYLOG_CLIENT_HANDSHAKE, CH_KEYLOG_SERVER_HANDSHAKE,
                                          CH_KEYLOG_CLIENT_TRAFFIC, CH_KEYLOG_SERVER_TRAFFIC};
    static const uint8_t zero[SHA256_LEN] = {0};
    CHECK(logged_count == 8);
    CHECK(client_io == 4 && server_io == 4);
    for (size_t i = 0; i < 4; i++) {
        const uint8_t *client_random = NULL;
        const uint8_t *server_random = NULL;
        const uint8_t *from_client = logged_secret(0, labels[i], &client_random);
        const uint8_t *from_server = logged_secret(1, labels[i], &server_random);
        CHECK(from_client != NULL && from_server != NULL);
        if (from_client == NULL || from_server == NULL) {
            continue;
        }
        CHECK(memcmp(from_client, from_server, SHA256_LEN) == 0);
        CHECK(memcmp(client_random, server_random, CH_KEYLOG_RANDOM_LEN) == 0);
        CHECK(memcmp(from_client, zero, SHA256_LEN) != 0);
    }
}

// The rsa_pss identity alone, because the client below pins its modulus
// and a pinned client offers the one signature scheme its build names.
// bin/srv_rec_test provisions both; here the pin picks the slot, so the
// unprovisioned one would make the server decline the only scheme the
// client offers.
static void server_config(ch_cfg *cfg) {
    memset(cfg, 0, sizeof *cfg);
    cfg->buf = srv_buf;
    cfg->buf_len = sizeof srv_buf;
    cfg->send = never_send;
    cfg->recv = never_recv;
    cfg->srv.cookie_key = cookie_key;
    cfg->srv.on_record_out = sink;
    cfg->io = &server_io;

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
}

static void client_config(ch_cfg *cfg) {
    memset(cfg, 0, sizeof *cfg);
    cfg->buf = cli_buf;
    cfg->buf_len = sizeof cli_buf;
    cfg->send = never_send;
    cfg->recv = never_recv;
    // The pin: the server's own provisioned modulus, so CertificateVerify
    // verifies against the key that signed it.
    cfg->server_pubkey = rsa_sign_2048_n;
    cfg->server_pubkey_len = sizeof rsa_sign_2048_n;
    cfg->io = &client_io;
}

// Moves everything the client owes into the server, and everything the
// server pushes back into to_client. Returns 0 on the first driver error.
static int client_to_server(ch_record *client, ch_record *server) {
    uint8_t wire[WIRE_MAX];
    size_t total = 0;
    for (;;) {
        size_t n = 0;
        int rc = ch_record_out(client, wire + total, sizeof wire - total, &n);
        CHECK(rc == CH_OK);
        if (rc != CH_OK) {
            return 0;
        }
        if (n == 0) {
            break;
        }
        total += n;
    }
    if (total == 0) {
        return 1;
    }
    size_t consumed = 0;
    int rc = ch_srv_record_in(server, wire, total, &consumed);
    if (rc != CH_OK) {
        if (!expect_refusal) {
            (void)fprintf(stderr, "server refused the client's bytes: rc=%d alert=%u\n", rc,
                          ch_record_alert(server));
        }
        return 0;
    }
    CHECK(consumed == total);
    return 1;
}

// Moves everything the server pushed into the client.
static int server_to_client(ch_record *client) {
    if (to_client.len == 0) {
        return 1;
    }
    size_t consumed = 0;
    int rc = ch_record_in(client, to_client.bytes, to_client.len, &consumed);
    if (rc != CH_OK) {
        if (!expect_refusal) {
            (void)fprintf(stderr, "client refused the server's flight: rc=%d alert=%u\n", rc,
                          ch_record_alert(client));
        }
        return 0;
    }
    CHECK(consumed == to_client.len);
    to_client.len = 0;
    return 1;
}

// The handshake, from two fresh sessions to whatever state the rounds
// reach. Returns the number of rounds it took.
static int run_handshake(ch_record *client, ch_record *server, const ch_cfg *ccfg,
                         const ch_cfg *scfg) {
    to_client.len = 0;
    records_pushed = 0;
    logged_count = 0;
    client_io = 0;
    server_io = 0;
    CHECK(ch_srv_record_init(server, scfg) == CH_OK);
    CHECK(ch_record_init(client, ccfg) == CH_OK);
    // Four rounds is more than the handshake needs and fewer than a loop
    // that never ends: one round trip completes it without a
    // HelloRetryRequest, and the client Finished takes a second pass
    // through client_to_server.
    int rounds = 0;
    while (rounds < 4 && (ch_record_state(client) != CH_ST_CONNECTED ||
                          ch_record_state(server) != CH_ST_CONNECTED)) {
        if (!client_to_server(client, server)) {
            break;
        }
        // Once both ends are connected, what the server pushed after the
        // client Finished is post-handshake and belongs to ch_read, which
        // the ticket cases hand it to.
        if (ch_record_state(client) == CH_ST_CONNECTED &&
            ch_record_state(server) == CH_ST_CONNECTED) {
            rounds++;
            break;
        }
        if (!server_to_client(client)) {
            break;
        }
        rounds++;
    }
    return rounds;
}

#include "rec_close_tests.h"
#include "rec_coalesced_tests.h"
#include "rec_read_tests.h"
#include "rec_resume_tests.h"

int main(void) {
    static ch_record client;
    static ch_record server;
    ch_cfg ccfg;
    ch_cfg scfg;

    server_config(&scfg);
    client_config(&ccfg);

    int rounds = run_handshake(&client, &server, &ccfg, &scfg);
    CHECK(ch_record_state(&client) == CH_ST_CONNECTED);
    CHECK(ch_record_state(&server) == CH_ST_CONNECTED);
    // The claim this binary exists for.
    CHECK(io_calls == 0);
    // Both ends report the group the client's build offers, which the
    // server selected out of the two it holds.
    CHECK(client.t.group == LOOP_GROUP && server.t.group == LOOP_GROUP);

    // RFC 9846 section 7.5: both ends derive exporter_master from the
    // same transcript, so one label and one context give one answer on
    // each side. A wrong context must not, or the context is not bound.
    static const uint8_t binding[3] = {'c', 't', 'x'};
    uint8_t from_client[SHA256_LEN];
    uint8_t from_server[SHA256_LEN];
    uint8_t other[SHA256_LEN];
    CHECK(ch_export(&client.t, "EXPORTER-Channel-Binding", binding, sizeof binding, from_client,
                    sizeof from_client) == CH_OK);
    CHECK(ch_export(&server.t, "EXPORTER-Channel-Binding", binding, sizeof binding, from_server,
                    sizeof from_server) == CH_OK);
    CHECK(memcmp(from_client, from_server, SHA256_LEN) == 0);
    CHECK(ch_export(&server.t, "EXPORTER-Channel-Binding", NULL, 0, other, sizeof other) == CH_OK);
    CHECK(memcmp(from_client, other, SHA256_LEN) != 0);
    check_logs_agree();

    // A secret that is all zero is one that was never derived.
    static const uint8_t zero[SHA256_LEN] = {0};
    CHECK(memcmp(from_client, zero, SHA256_LEN) != 0);

    // ch_read on the connected client, over records that arrive apart.
    // It ends the client's session, which the run below starts afresh.
    test_read_waits_for_records(&client, &server);

    // The same run against a pin that is not this server's key. Without
    // it the pass above would hold for a client that verified nothing,
    // which is the reading a loopback invites: both halves are ours, so
    // agreement is the cheap outcome. One flipped bit in the modulus
    // makes rsa_pss_verify refuse the CertificateVerify, and the client
    // must end dead with decrypt_error rather than connected.
    static uint8_t wrong_pin[sizeof rsa_sign_2048_n];
    memcpy(wrong_pin, rsa_sign_2048_n, sizeof wrong_pin);
    wrong_pin[sizeof wrong_pin - 1] ^= 0x02; // the modulus stays odd
    ccfg.server_pubkey = wrong_pin;
    io_calls = 0;
    expect_refusal = 1;
    (void)run_handshake(&client, &server, &ccfg, &scfg);
    CHECK(ch_record_state(&client) == CH_ST_FAILED);
    CHECK(ch_record_alert(&client) == ALERT_DECRYPT_ERROR);
    CHECK(io_calls == 0);
    // The client refused CertificateVerify, which comes before the
    // server Finished, so it derived its handshake secrets and never its
    // application ones: two rows, both handshake labels.
    const uint8_t *unused = NULL;
    CHECK(logged_secret(0, CH_KEYLOG_CLIENT_HANDSHAKE, &unused) != NULL);
    CHECK(logged_secret(0, CH_KEYLOG_SERVER_HANDSHAKE, &unused) != NULL);
    CHECK(logged_secret(0, CH_KEYLOG_CLIENT_TRAFFIC, &unused) == NULL);
    CHECK(logged_secret(0, CH_KEYLOG_SERVER_TRAFFIC, &unused) == NULL);
    // A dead session exports nothing: the secret went with the wipe.
    CHECK(ch_export(&client.t, "EXPORTER-Channel-Binding", NULL, 0, other, sizeof other) ==
          CH_EINVAL);

    test_resumption();

    // The client Finished and the first application record in one call.
    server_config(&scfg);
    client_config(&ccfg);
    test_finished_and_data_in_one_delivery(&client, &server, &ccfg, &scfg);

    // Each side's close_notify closes that side's direction alone.
    server_config(&scfg);
    client_config(&ccfg);
    test_close_one_direction(&client, &server, &ccfg, &scfg);

    if (failures == 0) {
        (void)printf("rec_loop: a whole handshake over group 0x%04x in %d rounds, 0 socket"
                     " calls; both ends export one secret and log the same four; ch_read"
                     " waits between records; a wrong pin refused; a ticket resumes with no"
                     " certificate; a close_notify closes one direction and ch_read sends"
                     " nothing\n",
                     (unsigned)LOOP_GROUP, rounds);
        return 0;
    }
    (void)fprintf(stderr, "rec_loop: %d failures\n", failures);
    return 1;
}
