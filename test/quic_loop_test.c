// Both QUIC drivers against each other in one process, over CRYPTO bytes
// and no packets: this tree's client (quic.c) and this tree's server
// (srv_quic.c) in one ROLE=both object, the object colibri links. It
// exists for resumption: the QUIC Interop Runner's resumption case has a
// client make a full handshake, keep the NewSessionTicket, and resume with
// it on a second connection that carries no Certificate.
//
// The Makefile builds it twice, once per trust mode colibri builds.
// bin/quic_loop_test is TRUST=raw-ecdsa, colibri's runner image: the
// client pins the server's P-256 key for the full handshake, takes the
// ticket at the 1-RTT level, and resumes with it. bin/quic_loop_webpki is
// TRUST=webpki, colibri's local checks: the server presents the r2 corpus
// chain with its leaf key, the client verifies it, resumes the ticket the
// full handshake left, and completes a full handshake in one connection
// when a server with another ticket key declines that ticket. The same
// build runs the SPKI pin configurations (test/quic_loop_pins.h).
//
// The keys agree when a packet one end seals at the 1-RTT level opens at
// the other, which is what the two cases below check after each
// handshake. The raw build also fails each end on purpose and has it seal
// the one CONNECTION_CLOSE each level owes, which the other end opens
// (test/quic_loop_close.h).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "handshake_message.h"
#include "p256_sign_vectors.h"
#include "rand.h"
#include "srv_quic.h"
#include "srv_ticket.h"
#ifdef CH_TRUST_WEBPKI
#include "webpki_ticket.h"
#endif

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

// What the server pushed, per encryption level, and how many messages at
// each level.
static struct {
    uint8_t bytes[3][4096];
    size_t len[3];
} from_server;

static int sink(void *io, uint8_t level, const uint8_t *p, size_t n) {
    (void)io;
    if (level > CH_LEVEL_APPLICATION || from_server.len[level] + n > sizeof from_server.bytes[0]) {
        return -1;
    }
    memcpy(from_server.bytes[level] + from_server.len[level], p, n);
    from_server.len[level] += n;
    return 0;
}

static void level_ready(void *io, uint8_t level, uint8_t direction) {
    (void)io;
    (void)level;
    (void)direction;
}

// The one ticket the client keeps, as a caller stores it.
static struct {
    uint8_t identity[CH_TICKET_ID_MAX];
    size_t identity_len;
    uint8_t psk[HKDF_HASH_MAX];
    size_t psk_len;
    uint32_t lifetime_s;
    uint32_t age_add;
#ifdef CH_TRUST_WEBPKI
    uint8_t binding[SHA256_LEN];
#endif
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
    kept.lifetime_s = ticket->lifetime_s;
    kept.age_add = ticket->age_add;
#ifdef CH_TRUST_WEBPKI
    memcpy(kept.binding, ticket->binding, SHA256_LEN);
#endif
    kept.count++;
}

static const uint8_t cert_der[4] = {0x30, 0x02, 0x05, 0x00};
static const ch_cert chain[1] = {
    {cert_der, sizeof cert_der}
};
static const uint8_t cookie_key[SHA256_LEN] = {7};
static const uint8_t ticket_key[SRV_TICKET_KEY_LEN] = {
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
static const uint8_t params[4] = {0x01, 0x02, 0x03, 0x04};
static const uint8_t alpn_interop[10] = {'h', 'q', '-', 'i', 'n', 't', 'e', 'r', 'o', 'p'};
static const uint8_t alpn_h3[2] = {'h', '3'};
static const ch_alpn_protocol server_alpn[2] = {
    {alpn_interop, sizeof alpn_interop},
    {alpn_h3,      sizeof alpn_h3     }
};

#define LOOP_NOW 1700000000U

static uint8_t server_buf[CH_MIN_RXBUF];
static uint8_t client_buf[CH_MIN_RXBUF];

static void server_config(ch_cfg *cfg) {
    memset(cfg, 0, sizeof *cfg);
    cfg->buf = server_buf;
    cfg->buf_len = sizeof server_buf;
    cfg->alpn_protocols = server_alpn;
    cfg->alpn_count = 2;
    cfg->transport_params = params;
    cfg->transport_params_len = sizeof params;
    cfg->on_level_ready = level_ready;
    cfg->srv.cookie_key = cookie_key;
    cfg->srv.on_crypto_out = sink;
    cfg->srv.ticket_key = ticket_key;
    cfg->srv.now_seconds = LOOP_NOW;
    cfg->srv.ecdsa_p256.chain = chain;
    cfg->srv.ecdsa_p256.chain_count = 1;
    cfg->srv.ecdsa_p256.priv = p256_sign_vectors[0].priv;
    cfg->srv.ecdsa_p256.priv_len = sizeof p256_sign_vectors[0].priv;
    cfg->srv.ecdsa_p256.pub = p256_sign_vectors[0].pub;
    cfg->srv.ecdsa_p256.pub_len = sizeof p256_sign_vectors[0].pub;
}

// The client half both builds share: one offered protocol, the transport
// parameters RFC 9001 section 8.2 requires, and the ticket callback.
static void client_config(ch_cfg *cfg, const ch_alpn_protocol *alpn) {
    memset(cfg, 0, sizeof *cfg);
    cfg->buf = client_buf;
    cfg->buf_len = sizeof client_buf;
    cfg->alpn_protocols = alpn;
    cfg->alpn_count = 1;
    cfg->transport_params = params;
    cfg->transport_params_len = sizeof params;
    cfg->on_level_ready = level_ready;
    cfg->on_ticket = keep_ticket;
}

// The kept ticket as a resuming client presents it.
static void present_ticket(ch_cfg *cfg) {
    cfg->psk = kept.psk;
    cfg->psk_len = kept.psk_len;
    cfg->psk_id = kept.identity;
    cfg->psk_id_len = kept.identity_len;
    cfg->resumption = 1;
    cfg->obfuscated_age = kept.age_add + 1000;
#ifdef CH_TRUST_WEBPKI
    cfg->ticket_binding = kept.binding;
#endif
}

static ch_quic client;
static ch_quic server;

// One handshake over CRYPTO bytes, the ticket after it, and nothing else.
// Returns 1 when both ends are connected, and 0 at the first refusal.
static int run_quic(const ch_cfg *ccfg, const ch_cfg *scfg) {
    static uint8_t buf[4096];
    size_t n = 0;
    memset(&from_server, 0, sizeof from_server);
    if (ch_quic_init(&client, ccfg) != CH_OK || ch_srv_quic_init(&server, scfg) != CH_OK) {
        return 0;
    }
    if (ch_quic_crypto_out(&client, CH_LEVEL_INITIAL, buf, sizeof buf, &n) != CH_OK ||
        ch_srv_quic_crypto_in(&server, CH_LEVEL_INITIAL, buf, n) != CH_OK) {
        return 0;
    }
    if (ch_quic_crypto_in(&client, CH_LEVEL_INITIAL, from_server.bytes[CH_LEVEL_INITIAL],
                          from_server.len[CH_LEVEL_INITIAL]) != CH_OK ||
        ch_quic_crypto_in(&client, CH_LEVEL_HANDSHAKE, from_server.bytes[CH_LEVEL_HANDSHAKE],
                          from_server.len[CH_LEVEL_HANDSHAKE]) != CH_OK) {
        return 0;
    }
    if (ch_quic_crypto_out(&client, CH_LEVEL_HANDSHAKE, buf, sizeof buf, &n) != CH_OK ||
        ch_srv_quic_crypto_in(&server, CH_LEVEL_HANDSHAKE, buf, n) != CH_OK) {
        return 0;
    }
    return ch_quic_state(&client) == CH_ST_CONNECTED && ch_quic_state(&server) == CH_ST_CONNECTED;
}

// Hands the server's 1-RTT CRYPTO bytes, the NewSessionTicket, to the
// client.
static void take_ticket(void) {
    CHECK(from_server.len[CH_LEVEL_APPLICATION] > 0);
    CHECK(ch_quic_crypto_in(&client, CH_LEVEL_APPLICATION, from_server.bytes[CH_LEVEL_APPLICATION],
                            from_server.len[CH_LEVEL_APPLICATION]) == CH_OK);
}

// The 1-RTT keys agree: a short-header packet the server seals, with an
// empty connection ID and a two-byte packet number, opens at the client.
static void check_keys_agree(void) {
    static const uint8_t hdr[3] = {0x41, 0x00, 0x05};
    static const uint8_t pt[24] = {'r', 'e', 's', 'u', 'm', 'e', 'd'};
    uint8_t pkt[64];
    size_t pkt_len = 0;
    CHECK(ch_quic_seal(&server, CH_LEVEL_APPLICATION, 5, 2, hdr, sizeof hdr, pt, sizeof pt, pkt,
                       sizeof pkt, &pkt_len) == CH_OK);
    uint8_t key_set = 0;
    uint64_t pn = 0;
    size_t pt_len = 0;
    CHECK(ch_quic_open(&client, CH_LEVEL_APPLICATION, pkt, pkt_len, 1, 0, 0, &key_set, &pn,
                       &pt_len) == CH_OK);
    CHECK(pn == 5 && pt_len == sizeof pt && memcmp(pkt + sizeof hdr, pt, sizeof pt) == 0);
}

// How many Handshake-level messages the server sent, counted by walking
// their four-byte headers.
static size_t handshake_messages(void) {
    size_t count = 0;
    size_t off = 0;
    const uint8_t *b = from_server.bytes[CH_LEVEL_HANDSHAKE];
    while (off + 4 <= from_server.len[CH_LEVEL_HANDSHAKE]) {
        off += 4 + (((size_t)b[off + 1] << 16) | ((size_t)b[off + 2] << 8) | b[off + 3]);
        count++;
    }
    return count;
}

#ifdef CH_PIN_ECDSA
#include "quic_loop_close.h"
#include "quic_loop_raw.h"
#endif
#ifdef CH_TRUST_WEBPKI
#include "quic_loop_webpki.h"
#endif
// The pin rows run quic_loop_webpki.h's client and server.
#ifdef CH_TRUST_WEBPKI
#include "quic_loop_pins.h"
#endif
// The suite rows run quic_loop_webpki.h's client and server.
#ifdef CH_SUITE_AES_GCM
#include "quic_loop_suites.h"
#endif

int main(void) {
#ifdef CH_PIN_ECDSA
    test_raw_resumption();
    test_close_after_failure();
#endif
#ifdef CH_TRUST_WEBPKI
    test_quic_hello_boundary();
    test_webpki_resumption();
    test_webpki_pins();
#endif
#ifdef CH_SUITE_AES_GCM
    test_quic_suites();
#endif
    if (failures == 0) {
        (void)printf("quic_loop: a QUIC client resumed a ticket from this tree's server with no"
                     " certificate, and the 1-RTT keys agree\n");
    }
    return failures != 0;
}
