// This tree's TRUST=webpki tcp-nonblocking client against this tree's
// tcp-nonblocking server in one process, over the object that carries both:
// ROLE=both TRANSPORT=tcp-nonblocking TRUST=webpki. The server presents the r2
// corpus chain and signs with its leaf key (test/webpki_r2_chain.h), so
// the client runs the whole chain walk against a real server flight.
//
// It exists for the resumption offer of docs/decisions.md 55. A resuming
// webpki hello offers the certificate path beside the ticket, so the
// server may take either one:
//   - with the key that sealed the ticket it resumes: no Certificate, and
//     both ends report psk_selected;
//   - with another ticket key it cannot open the ticket, declines it, and
//     the same connection completes as a full handshake whose chain the
//     client checks as a fresh handshake does, the hostname and the
//     anchor included.
// This server answers a hello that offers no scheme and whose ticket it
// passes over with missing_extension, so a client that dropped the
// schemes from its resuming hello fails the decline rows here.
//
// It also runs SPKI pins alone against that chain (docs/decisions.md 65):
// a pin on the leaf's key passes with no hostname, anchor or clock, its
// ticket resumes under that pin alone, and a pin on the intermediate's
// key is refused with bad_certificate.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "handshake_message.h"
#include "rand.h"
#include "rec.h"
#include "record.h"
#include "srv_rec.h"
#include "srv_ticket.h"
#include "tls.h"
#include "webpki_ticket.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// A counter, not entropy: both ends draw from it, so the two key shares
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

static const uint8_t cookie_key[SHA256_LEN] = {7};
static const uint8_t ticket_key[SRV_TICKET_KEY_LEN] = {
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80};
static const uint8_t other_ticket_key[SRV_TICKET_KEY_LEN] = {
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30};

// The server's clock when it issues and judges tickets.
#define LOOP_NOW 1700000000U

// The server's buffer holds the client's hello, which carries the
// 1216-byte hybrid share and the ticket, and this build's floor is larger
// than that hello.
_Static_assert(CH_MIN_RXBUF >= REC_HDR + CH_HELLO_MAX, "the server buffer holds any hello");
static uint8_t srv_buf[CH_MIN_RXBUF];
static uint8_t cli_buf[CH_MIN_RXBUF];

// What the server pushed and the client has not read, and how many
// records since the handshake started.
static struct {
    uint8_t bytes[4096];
    size_t len;
    size_t off;
} to_client;
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

// The client's recv once connected: the records the server pushed after
// the handshake, the ticket among them, and then none (rec.h).
static int held_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    size_t left = to_client.len - to_client.off;
    size_t take = n < left ? n : left;
    memcpy(p, to_client.bytes + to_client.off, take);
    to_client.off += take;
    return (int)take;
}

static int unused_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    return -1;
}

// The one ticket the client keeps, as a caller stores it.
static struct {
    uint8_t identity[CH_TICKET_ID_MAX];
    size_t identity_len;
    uint8_t psk[HKDF_HASH_MAX];
    size_t psk_len;
    uint32_t age_add;
    uint8_t binding[SHA256_LEN];
    size_t count;
} kept;

static void keep_ticket(void *io, const ch_ticket *ticket) {
    (void)io;
    CHECK(ticket->identity_len <= sizeof kept.identity);
    memcpy(kept.identity, ticket->identity, ticket->identity_len);
    kept.identity_len = ticket->identity_len;
    CHECK(ticket->psk_len <= sizeof kept.psk);
    memcpy(kept.psk, ticket->psk, ticket->psk_len);
    kept.psk_len = ticket->psk_len;
    kept.age_add = ticket->age_add;
    memcpy(kept.binding, ticket->binding, SHA256_LEN);
    kept.count++;
}

static void server_config(ch_cfg *cfg, const uint8_t *key) {
    memset(cfg, 0, sizeof *cfg);
    cfg->buf = srv_buf;
    cfg->buf_len = sizeof srv_buf;
    cfg->send = unused_send;
    cfg->recv = held_recv;
    cfg->srv.cookie_key = cookie_key;
    cfg->srv.on_record_out = sink;
    cfg->srv.ticket_key = key;
    cfg->srv.now_seconds = LOOP_NOW;
    CHECK(r2_identity(&cfg->srv.ecdsa_p256));
}

// The client that verifies the r2 chain under root for hostname, presenting
// the kept ticket, bound to that configuration, when present is set.
static void client_config(ch_cfg *cfg, const webpki_corpus_anchor *root, const char *hostname,
                          int present) {
    memset(cfg, 0, sizeof *cfg);
    cfg->buf = cli_buf;
    cfg->buf_len = sizeof cli_buf;
    cfg->send = unused_send;
    cfg->recv = held_recv;
    cfg->on_ticket = keep_ticket;
    r2_trust(cfg, root, hostname);
    if (!present) {
        return;
    }
    cfg->psk = kept.psk;
    cfg->psk_len = kept.psk_len;
    cfg->psk_id = kept.identity;
    cfg->psk_id_len = kept.identity_len;
    cfg->resumption = 1;
    cfg->obfuscated_age = kept.age_add + 5000;
    // The binding on_ticket handed over names s3.example.test and
    // root_p384. A row that presents the ticket under another name or
    // anchor binds it again, as a caller that stored it there would have.
    uint8_t config_hash[SHA256_LEN];
    webpki_ticket_config_hash(cfg, config_hash);
    webpki_ticket_binding(kept.psk, kept.psk_len, config_hash, kept.binding);
    cfg->ticket_binding = kept.binding;
}

static ch_record client;
static ch_record server;

// Moves what the client staged into the server. Returns 0 on a refusal.
static int client_to_server(void) {
    uint8_t wire[REC_HDR + CH_TX_STAGE + 64];
    size_t n = 0;
    CHECK(ch_record_out(&client, wire, sizeof wire, &n) == CH_OK);
    if (n == 0) {
        return 1;
    }
    size_t consumed = 0;
    return ch_srv_record_in(&server, wire, n, &consumed) == CH_OK && consumed == n;
}

// Moves what the server pushed into the client. Returns 0 on a refusal.
static int server_to_client(void) {
    size_t left = to_client.len - to_client.off;
    if (left == 0) {
        return 1;
    }
    size_t consumed = 0;
    int rc = ch_record_in(&client, to_client.bytes + to_client.off, left, &consumed);
    to_client.off += consumed;
    return rc == CH_OK;
}

// One handshake between fresh sessions, then the ticket the server sent
// after it, through ch_read. The client is connected once ch_record_out
// has handed its Finished over, and what the server pushes after that is
// post-handshake, for ch_read. Returns 1 when both ends connected.
static int run(const ch_cfg *ccfg, const ch_cfg *scfg) {
    memset(&to_client, 0, sizeof to_client);
    records_pushed = 0;
    CHECK(ch_srv_record_init(&server, scfg) == CH_OK);
    CHECK(ch_record_init(&client, ccfg) == CH_OK);
    for (int round = 0; round < 4; round++) {
        if (!client_to_server()) {
            return 0;
        }
        if (ch_record_state(&client) == CH_ST_CONNECTED) {
            break;
        }
        if (!server_to_client()) {
            return 0;
        }
    }
    if (ch_record_state(&client) != CH_ST_CONNECTED ||
        ch_record_state(&server) != CH_ST_CONNECTED) {
        return 0;
    }
    uint8_t got[16];
    CHECK(ch_read(&client.t, got, sizeof got) == CH_RECORD_AGAIN);
    return 1;
}

// A server holding key, which did not seal the kept ticket, declines it,
// and a client whose trust the r2 chain fails refuses the Certificate
// with the walk's alert and ends dead.
static void check_declined_chain_refused(const uint8_t *key, const webpki_corpus_anchor *root,
                                         const char *hostname, uint8_t alert) {
    ch_cfg scfg;
    ch_cfg ccfg;
    server_config(&scfg, key);
    client_config(&ccfg, root, hostname, 1);
    CHECK(!run(&ccfg, &scfg));
    CHECK(ch_record_state(&client) == CH_ST_FAILED && ch_record_alert(&client) == alert);
    CHECK(client.t.psk_selected == 0);
}

// The one pin a pins-alone client carries.
static uint8_t loop_pin[1][SHA256_LEN];

// The pin of entry index of the r2 chain the server presents, the leaf at
// 0 and the intermediate at 1. server_config must have split the chain.
static int r2_pin(size_t index) {
    webpki_cert parsed;
    uint8_t alert = ALERT_BAD_CERTIFICATE;
    if (webpki_parse_certificate(r2_chain[index].der, r2_chain[index].len, index != 0, &parsed,
                                 &alert) != CH_OK) {
        return 0;
    }
    sha256_of(parsed.spki_tlv, parsed.spki_tlv_len, loop_pin[0]);
    return 1;
}

// A client with loop_pin alone: no hostname, anchor or clock, presenting
// the kept ticket, with the binding on_ticket gave it, when present is set.
static void pins_alone_config(ch_cfg *cfg, int present) {
    memset(cfg, 0, sizeof *cfg);
    cfg->buf = cli_buf;
    cfg->buf_len = sizeof cli_buf;
    cfg->send = unused_send;
    cfg->recv = held_recv;
    cfg->on_ticket = keep_ticket;
    cfg->spki_pins = (const uint8_t *)loop_pin;
    cfg->spki_pin_count = 1;
    if (present) {
        cfg->psk = kept.psk;
        cfg->psk_len = kept.psk_len;
        cfg->psk_id = kept.identity;
        cfg->psk_id_len = kept.identity_len;
        cfg->resumption = 1;
        cfg->obfuscated_age = kept.age_add + 5000;
        cfg->ticket_binding = kept.binding;
    }
}

// Pins alone against the r2 chain: the leaf's pin passes and binds its
// ticket, which resumes under that pin and no other, and the
// intermediate's pin is refused, because only the leaf's key counts.
static void test_pins_alone(void) {
    ch_cfg scfg;
    ch_cfg ccfg;
    server_config(&scfg, ticket_key);
    CHECK(r2_pin(0));
    pins_alone_config(&ccfg, 0);
    size_t count = kept.count;
    CHECK(run(&ccfg, &scfg));
    CHECK(client.t.psk_selected == 0 && client.t.server_cert_type == CH_CERT_TYPE_X509);
    CHECK(kept.count == count + 1);
    uint8_t hash[SHA256_LEN];
    uint8_t binding[SHA256_LEN];
    webpki_ticket_config_hash(&ccfg, hash);
    webpki_ticket_binding(kept.psk, kept.psk_len, hash, binding);
    CHECK(memcmp(binding, kept.binding, SHA256_LEN) == 0);
    pins_alone_config(&ccfg, 1);
    CHECK(run(&ccfg, &scfg));
    CHECK(client.t.psk_selected == 1 && server.t.psk_selected == 1 && records_pushed == 4);
    CHECK(r2_pin(1));
    pins_alone_config(&ccfg, 1);
    static ch_record probe;
    CHECK(ch_record_init(&probe, &ccfg) == CH_EINVAL);
    pins_alone_config(&ccfg, 0);
    CHECK(!run(&ccfg, &scfg));
    CHECK(ch_record_state(&client) == CH_ST_FAILED &&
          ch_record_alert(&client) == ALERT_BAD_CERTIFICATE);
}

#include "webpki_loop_suites.h"

int main(void) {
    ch_cfg scfg;
    ch_cfg ccfg;

    // The full handshake: ServerHello, EncryptedExtensions, the 1037-byte
    // Certificate in three records of at most CH_TX_PT bytes,
    // CertificateVerify and Finished, then the ticket.
    server_config(&scfg, ticket_key);
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 0);
    CHECK(run(&ccfg, &scfg));
    CHECK(client.t.psk_selected == 0 && server.t.psk_selected == 0);
    CHECK(server.t.sigalg == SIGALG_ECDSA_P256_SHA256 && records_pushed == 8);
    CHECK(kept.count == 1);

    // The ticket resumes: ServerHello, EncryptedExtensions and Finished,
    // then a fresh ticket. The hello carried the certificate path beside
    // the ticket, and the server that selected the ticket names no scheme.
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 1);
    CHECK(run(&ccfg, &scfg));
    CHECK(client.t.psk_selected == 1 && server.t.psk_selected == 1);
    CHECK(server.t.sigalg == 0 && records_pushed == 4);
    CHECK(kept.count == 2);

    // A server with another ticket key declines it, and the connection
    // completes as a full handshake.
    server_config(&scfg, other_ticket_key);
    client_config(&ccfg, webpki_corpus_anchors_root_p384, "s3.example.test", 1);
    CHECK(run(&ccfg, &scfg));
    CHECK(client.t.psk_selected == 0 && server.t.psk_selected == 0);
    CHECK(server.t.sigalg == SIGALG_ECDSA_P256_SHA256 && records_pushed == 8);
    CHECK(client.t.server_cert_type == CH_CERT_TYPE_X509);
    CHECK(kept.count == 3);

    // That decline checks the chain as a fresh handshake does. The kept
    // ticket is the one the server holding other_ticket_key sealed, so
    // the server holding ticket_key is the one that declines it now.
    check_declined_chain_refused(ticket_key, webpki_corpus_anchors_root_p384, "other.example.test",
                                 ALERT_BAD_CERTIFICATE);
    check_declined_chain_refused(ticket_key, webpki_corpus_anchors_impostor_p384, "s3.example.test",
                                 ALERT_UNKNOWN_CA);
    test_pins_alone();
#ifdef CH_SUITE_AES_GCM
    check_suites();
#endif

    if (failures == 0) {
        (void)printf("webpki_loop: a full handshake over the r2 chain, a resumed ticket with no"
                     " certificate, and a declined ticket completed as a full handshake that"
                     " checked the hostname and the anchor\n");
        return 0;
    }
    (void)fprintf(stderr, "webpki_loop: %d failures\n", failures);
    return 1;
}
