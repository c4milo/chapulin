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
// (test/quic_loop_close.h), and runs whole handshakes in QUIC version 2,
// one of them after a Retry (test/quic_loop_version.h). Both builds hold a
// ticket to the QUIC version of the connection that issued it
// (test/quic_loop_ticket_versions.h). bin/quic_loop_session is the raw
// build under -DCH_RAND_SESSION: every session draws from the source its
// ch_cfg names, and test/quic_loop_session.h checks what each source
// handed out.
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

#ifdef CH_RAND_SESSION
#include "rand_session.h"
#else
// A counter, not entropy: both ends draw from it, so the two key shares
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

// What the server pushed, per encryption level, and how many messages at
// each level. The largest level here is the Handshake level of pins alone
// over the leaf_over_cert_max chain, whose Certificate is 6,106 bytes.
static struct {
    uint8_t bytes[3][8192];
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
    uint32_t quic_version;
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
    kept.quic_version = ticket->quic_version;
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
static const uint8_t ticket_key[CH_SRV_TICKET_KEY_LEN] = {
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

#ifdef CH_AES_RUNTIME
// The answers an AES=runtime row gives each end's ch_cfg.aes_instructions:
// the instructions present unless the row says otherwise
// (test/quic_loop_runtime.h).
static uint8_t server_aes = CH_AES_INSTRUCTIONS_PRESENT;
static uint8_t client_aes = CH_AES_INSTRUCTIONS_PRESENT;
#endif

static void server_config(ch_cfg *cfg) {
    memset(cfg, 0, sizeof *cfg);
    cfg->buf = server_buf;
    cfg->buf_len = sizeof server_buf;
    cfg->alpn_protocols = server_alpn;
    cfg->alpn_count = 2;
    cfg->transport_params = params;
    cfg->transport_params_len = sizeof params;
    cfg->quic_original_version = CH_QUIC_VERSION_1;
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
#ifdef CH_RAND_SESSION
    attach_source(cfg, &server_source);
#endif
#ifdef CH_AES_RUNTIME
    cfg->aes_instructions = server_aes;
#endif
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
    cfg->quic_original_version = CH_QUIC_VERSION_1;
    cfg->on_level_ready = level_ready;
    cfg->on_ticket = keep_ticket;
#ifdef CH_RAND_SESSION
    attach_source(cfg, &client_source);
#endif
#ifdef CH_AES_RUNTIME
    cfg->aes_instructions = client_aes;
#endif
}

// The kept ticket as a resuming client presents it, one second after it
// arrived, with the QUIC version it arrived in. The obfuscated age comes
// from a ch_ticket holding the kept age_add and nothing else, as a
// caller's copy does.
static void present_ticket(ch_cfg *cfg) {
    cfg->psk = kept.psk;
    cfg->psk_len = kept.psk_len;
    cfg->psk_id = kept.identity;
    cfg->psk_id_len = kept.identity_len;
    cfg->resumption = 1;
    cfg->ticket_quic_version = kept.quic_version;
    ch_ticket ticket;
    memset(&ticket, 0, sizeof ticket);
    ticket.age_add = kept.age_add;
    cfg->ticket_age_ms = 1000;
    cfg->ticket_lifetime_s = kept.lifetime_s;
    cfg->obfuscated_age = ch_ticket_obfuscated_age(&ticket, cfg->ticket_age_ms);
#ifdef CH_TRUST_WEBPKI
    cfg->ticket_binding = kept.binding;
#endif
}

// The ticket's age against its lifetime, which ch_quic_init judges before
// it builds a hello (handshake_post.h): an age equal to the lifetime is
// taken, and one millisecond more is refused with the session left dead.
// cfg presents the kept ticket, and leaves as it came.
static void check_ticket_age(ch_cfg *cfg) {
    static ch_quic probe;
    uint64_t age_ms = cfg->ticket_age_ms;
    cfg->ticket_age_ms = (uint64_t)kept.lifetime_s * 1000U;
    CHECK(ch_quic_init(&probe, cfg) == CH_OK);
    ch_quic_close(&probe);
    cfg->ticket_age_ms += 1;
    CHECK(ch_quic_init(&probe, cfg) == CH_EINVAL);
    CHECK(ch_quic_state(&probe) == CH_ST_FAILED);
    cfg->ticket_age_ms = age_ms;
}

static ch_quic client;
static ch_quic server;

// How many times choose_version_2, the server's choice in the version
// cases, fired.
static unsigned choose_calls;

static uint32_t choose_version_2(void *io) {
    (void)io;
    choose_calls++;
    return CH_QUIC_VERSION_2;
}

// One handshake over CRYPTO bytes, the ticket after it, and nothing else.
// A client that follows takes the server's negotiated version before it
// reads the server's first byte, as colibri does when the Version field of
// the server's first Initial packet differs from the client's
// (rfc9369.txt:240-244); test/quic_loop_version.h runs one that does not.
// Returns 1 when both ends are connected, and 0 at the first refusal.
static int run_quic_following(const ch_cfg *ccfg, const ch_cfg *scfg, int follow) {
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
    uint32_t chosen = ch_quic_negotiated_version(&server);
    if (follow && chosen != ch_quic_negotiated_version(&client) &&
        ch_quic_switch_version(&client, chosen) != CH_OK) {
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

static int run_quic(const ch_cfg *ccfg, const ch_cfg *scfg) {
    return run_quic_following(ccfg, scfg, 1);
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
// Both ends negotiated the version given, and a 1-RTT packet in the other
// version is one RFC 9369 section 4.1 makes each end drop: the seal is
// refused, and the open is refused before the packet is read or a failure
// counted.
static void check_keys_agree_in(uint32_t version) {
    static const uint8_t hdr[3] = {0x41, 0x00, 0x05};
    static const uint8_t pt[24] = {'r', 'e', 's', 'u', 'm', 'e', 'd'};
    uint32_t other = version == CH_QUIC_VERSION_1 ? CH_QUIC_VERSION_2 : CH_QUIC_VERSION_1;
    uint8_t pkt[64];
    size_t pkt_len = 0;
    CHECK(ch_quic_negotiated_version(&client) == version &&
          ch_quic_negotiated_version(&server) == version);
    CHECK(ch_quic_seal(&server, CH_LEVEL_APPLICATION, other, 5, 2, hdr, sizeof hdr, pt, sizeof pt,
                       pkt, sizeof pkt, &pkt_len) == CH_EINVAL);
    CHECK(ch_quic_seal(&server, CH_LEVEL_APPLICATION, version, 5, 2, hdr, sizeof hdr, pt, sizeof pt,
                       pkt, sizeof pkt, &pkt_len) == CH_OK);
    uint8_t key_set = 0;
    uint64_t pn = 0;
    size_t pt_len = 0;
    uint64_t failures_before = client.open_failures;
    CHECK(ch_quic_open(&client, CH_LEVEL_APPLICATION, other, pkt, pkt_len, 1, 0, 0, &key_set, &pn,
                       &pt_len) == CH_EINVAL);
    CHECK(client.open_failures == failures_before && pn == 0);
    CHECK(ch_quic_open(&client, CH_LEVEL_APPLICATION, version, pkt, pkt_len, 1, 0, 0, &key_set, &pn,
                       &pt_len) == CH_OK);
    CHECK(pn == 5 && pt_len == sizeof pt && memcmp(pkt + sizeof hdr, pt, sizeof pt) == 0);
}

static void check_keys_agree(void) {
    check_keys_agree_in(CH_QUIC_VERSION_1);
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
#include "quic_loop_version.h"
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
// The ticket version rows run each build's client and server.
#if defined(CH_PIN_ECDSA) || defined(CH_TRUST_WEBPKI)
#include "quic_loop_ticket_versions.h"
#endif
#ifdef CH_RAND_SESSION
#include "quic_loop_session.h"
#endif
#ifdef CH_AES_RUNTIME
#include "quic_loop_runtime.h"
#endif

int main(int argc, char **argv) {
#ifdef CH_AES_RUNTIME
    if (argc > 1 && strcmp(argv[1], "absent") == 0) {
        return test_quic_runtime_absent();
    }
#endif
    (void)argc;
    (void)argv;
#ifdef CH_PIN_ECDSA
    test_raw_resumption();
    test_close_after_failure();
    test_quic_version_2();
#endif
#ifdef CH_TRUST_WEBPKI
    test_quic_hello_boundary();
    test_webpki_resumption();
    test_webpki_pins();
#endif
#ifdef CH_SUITE_AES_GCM
    test_quic_suites();
#endif
#if defined(CH_PIN_ECDSA) || defined(CH_TRUST_WEBPKI)
    test_ticket_versions();
#endif
#ifdef CH_RAND_SESSION
    test_session();
#endif
#ifdef CH_AES_RUNTIME
    test_quic_runtime();
#endif
    if (failures == 0) {
        (void)printf("quic_loop: a QUIC client resumed a ticket from this tree's server with no"
                     " certificate, and the 1-RTT keys agree\n");
    }
    return failures != 0;
}
