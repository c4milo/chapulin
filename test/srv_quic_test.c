// The QUIC server driver end to end: this tree's own ClientHello, built by
// handshake_message.c, fed to srv_quic.c, and the flight it pushes back.
// docs/quic_server.md names this binary bin/srv_quic_test.
//
// Why the client's builder rather than a byte vector: the message a QUIC
// client sends is the thing the server has to read, and a vector written
// by hand beside the parser it feeds can drift with it. bin/srv_test holds
// the hand-written hello that pins the parser's format; this binary asks a
// different question -- whether the driver runs a whole flight -- and the
// two builders are on opposite sides of the connection, so neither can
// hide a mistake in the other.
//
// The first flight stops before the client Finished, which needs a
// client's transcript and key schedule. test/srv_quic_retry_tests.h runs one
// handshake to the end: ngtcp2's recorded hellos through a HelloRetryRequest,
// with the client Finished computed from this tree's key schedule.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ch_assert.h"
#include "handshake_message.h"
#include "p256_sign_vectors.h"
#include "rand.h"
#include "rsa_sign.h"
#include "rsa_sign_vectors.h"
#include "srv_auth.h"
#include "srv_quic.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

// A counter, not entropy: these cases compare structure and codes rather
// than bytes, and a fixed stream replays a failure exactly.
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

// What the sink and the two callbacks recorded, so main() can ask which
// level each fragment went out at and in what order.
#define MAX_FRAGS 32
static struct {
    uint8_t level[MAX_FRAGS];
    size_t len[MAX_FRAGS];
    size_t count;
    size_t total[3];
    uint8_t ready[3][2];
    const uint8_t *params;
    size_t params_len;
} seen;

static int sink(void *io, uint8_t level, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    if (seen.count < MAX_FRAGS) {
        seen.level[seen.count] = level;
        seen.len[seen.count] = n;
    }
    seen.count++;
    if (level < 3) {
        seen.total[level] += n;
    }
    return 0;
}

static void level_ready(void *io, uint8_t level, uint8_t direction) {
    (void)io;
    if (level < 3 && direction < 2) {
        seen.ready[level][direction] = 1;
    }
}

static void got_params(void *io, const uint8_t *body, size_t n) {
    (void)io;
    seen.params = body;
    seen.params_len = n;
}

// One certificate the chain pointer names. No line of the flight reads a
// byte of it: a ROLE=server object links no X.509 reader at all.
static const uint8_t cert_der[4] = {0x30, 0x02, 0x05, 0x00};
static const ch_cert chain[1] = {
    {cert_der, sizeof cert_der}
};
static const uint8_t cookie_key[SHA256_LEN] = {7};
static const uint8_t client_params[] = {0x01, 0x02, 0x03, 0x04};
// The server's transport parameters at the largest body the API admits,
// so the flight below stages the largest EncryptedExtensions a QUIC
// server can send. SRV_ENCRYPTED_EXTENSIONS_MAX first left this body out,
// and a server failed that message with CH_ECAP past about 45 bytes.
static uint8_t server_params[CH_TRANSPORT_PARAMS_MAX];
static const uint8_t alpn_h3[] = {'h', '3'};
static const ch_alpn_protocol alpn[1] = {
    {alpn_h3, sizeof alpn_h3}
};

static uint8_t srv_buf[CH_MIN_RXBUF];

// RFC 9001 Appendix A's Destination Connection ID and Appendix A.3's
// server Initial packet: the header, the payload and the protected packet
// the RFC prints (rfc9001.txt:2462-2488).
//
// test/quic_initial_tests.h already holds quic_initial_seal to these same
// bytes. What this binary adds is the layer above it: whether the driver
// hands that call the right endpoint in a ROLE=server build. It did not,
// and nothing caught it, because no server test reached ch_quic_seal at
// all -- a client-labelled server would have failed its first Initial
// packet in both directions.
static const uint8_t APPENDIX_DCID[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
#define A3_HDR_LEN 20
#define A3_PN_LEN 2
#define A3_PN 1
#define A3_PAYLOAD 99
#define A3_PACKET (A3_HDR_LEN + A3_PAYLOAD + GCM_TAG)
#define A3_HDR_HEX "c1000000010008f067a5502a4262b50040750001"
#define A3_PAYLOAD_HEX                                                                             \
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739"                             \
    "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94"                             \
    "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00"                             \
    "020304"
#define A3_PACKET_HEX                                                                              \
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a"                             \
    "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3"                             \
    "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84"                             \
    "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4"                             \
    "2158407dd074ee"

static size_t unhex(const char *hex, uint8_t *out) {
    size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned v = 0;
        (void)sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}

// The driver seals an Initial packet under this endpoint's own labels.
// A server writes under "server in", so the bytes must be Appendix A.3's
// server packet and not the client's.
static void test_initial_seal_uses_the_server_labels(void) {
    uint8_t hdr[A3_HDR_LEN];
    static uint8_t pt[A3_PAYLOAD];
    static uint8_t want[A3_PACKET];
    CHECK(unhex(A3_HDR_HEX, hdr) == sizeof hdr);
    CHECK(unhex(A3_PAYLOAD_HEX, pt) == sizeof pt);
    CHECK(unhex(A3_PACKET_HEX, want) == sizeof want);

    // The side ch_srv_quic_init gives a session, which a ROLE=both build
    // reads and a ROLE=server build fixes.
    ch_quic q;
    memset(&q, 0, sizeof q);
    q.t.state = CH_ST_START;
    q.endpoint = CH_QUIC_ENDPOINT_SERVER;
    CHECK(ch_quic_initial_keys(&q, APPENDIX_DCID, sizeof APPENDIX_DCID) == CH_OK);

    static uint8_t out[A3_PACKET];
    size_t out_len = 0;
    CHECK(ch_quic_seal(&q, CH_LEVEL_INITIAL, A3_PN, A3_PN_LEN, hdr, sizeof hdr, pt, sizeof pt, out,
                       sizeof out, &out_len) == CH_OK);
    CHECK(out_len == sizeof out);
    CHECK(memcmp(out, want, sizeof want) == 0);
}

// The staging frame holds the largest EncryptedExtensions exactly: the
// longest ALPN name and the largest transport parameters body build at
// SRV_ENCRYPTED_EXTENSIONS_MAX, and one byte less refuses them.
static void test_encrypted_extensions_max(void) {
    static uint8_t name[CH_ALPN_NAME_MAX];
    memset(name, 'n', sizeof name);
    const ch_alpn_protocol longest = {name, sizeof name};
    static uint8_t msg[SRV_ENCRYPTED_EXTENSIONS_MAX];
    CHECK(srv_build_encrypted_extensions(msg, sizeof msg, 0, &longest, server_params,
                                         sizeof server_params) == sizeof msg);
    CHECK(srv_build_encrypted_extensions(msg, sizeof msg - 1, 0, &longest, server_params,
                                         sizeof server_params) == 0);
}

// Both identities, because the hello this tree's client builds offers the
// signature scheme its PIN chose and the server has to hold the matching
// key. Provisioning both keeps the test independent of that axis.
static ch_rsa_priv rsa_key;

static void provision(ch_cfg *cfg) {
    cfg->srv.ecdsa_p256.chain = chain;
    cfg->srv.ecdsa_p256.chain_count = 1;
    cfg->srv.ecdsa_p256.priv = p256_sign_vectors[0].priv;
    cfg->srv.ecdsa_p256.priv_len = sizeof p256_sign_vectors[0].priv;
    cfg->srv.ecdsa_p256.pub = p256_sign_vectors[0].pub;
    cfg->srv.ecdsa_p256.pub_len = sizeof p256_sign_vectors[0].pub;

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

#ifdef CH_ROLE_BOTH
// A ROLE=both object holds both drivers, and a session takes its side
// from the init call that made it, not from the build (quic.c's
// CH_QUIC_SELF). A client session and a server session over one
// connection ID each open the Initial packet the other sealed, and the
// server's is RFC 9001 Appendix A.3's packet. The build first gave every
// session the server's labels, so the server discarded the client's
// first Initial packet every time.
static void test_both_roles_take_their_own_labels(const ch_cfg *server_cfg) {
    uint8_t hdr[A3_HDR_LEN];
    static uint8_t pt[A3_PAYLOAD];
    static uint8_t want[A3_PACKET];
    CHECK(unhex(A3_HDR_HEX, hdr) == sizeof hdr);
    CHECK(unhex(A3_PAYLOAD_HEX, pt) == sizeof pt);
    CHECK(unhex(A3_PACKET_HEX, want) == sizeof want);

    static uint8_t client_buf[CH_MIN_RXBUF];
    ch_cfg client_cfg;
    memset(&client_cfg, 0, sizeof client_cfg);
    client_cfg.buf = client_buf;
    client_cfg.buf_len = sizeof client_buf;
    client_cfg.alpn_protocols = alpn;
    client_cfg.alpn_count = 1;
    client_cfg.transport_params = client_params;
    client_cfg.transport_params_len = sizeof client_params;
    client_cfg.on_level_ready = level_ready;
    client_cfg.server_pubkey = rsa_sign_2048_n;
    client_cfg.server_pubkey_len = sizeof rsa_sign_2048_n;
    static ch_quic client;
    static ch_quic server;
    CHECK(ch_quic_init(&client, &client_cfg) == CH_OK);
    CHECK(ch_srv_quic_init(&server, server_cfg) == CH_OK);
    CHECK(ch_quic_initial_keys(&client, APPENDIX_DCID, sizeof APPENDIX_DCID) == CH_OK);
    CHECK(ch_quic_initial_keys(&server, APPENDIX_DCID, sizeof APPENDIX_DCID) == CH_OK);

    static uint8_t pkt[A3_PACKET];
    size_t pkt_len = 0;
    uint8_t key_set = 0;
    uint64_t pn = 0;
    size_t pt_len = 0;
    CHECK(ch_quic_seal(&server, CH_LEVEL_INITIAL, A3_PN, A3_PN_LEN, hdr, sizeof hdr, pt, sizeof pt,
                       pkt, sizeof pkt, &pkt_len) == CH_OK);
    CHECK(pkt_len == sizeof want && memcmp(pkt, want, sizeof want) == 0);
    CHECK(ch_quic_open(&client, CH_LEVEL_INITIAL, pkt, pkt_len, A3_HDR_LEN - A3_PN_LEN, 0, 0,
                       &key_set, &pn, &pt_len) == CH_OK);
    CHECK(pn == A3_PN && pt_len == sizeof pt);

    CHECK(ch_quic_seal(&client, CH_LEVEL_INITIAL, A3_PN, A3_PN_LEN, hdr, sizeof hdr, pt, sizeof pt,
                       pkt, sizeof pkt, &pkt_len) == CH_OK);
    CHECK(ch_quic_open(&server, CH_LEVEL_INITIAL, pkt, pkt_len, A3_HDR_LEN - A3_PN_LEN, 0, 0,
                       &key_set, &pn, &pt_len) == CH_OK);
    CHECK(pn == A3_PN && pt_len == sizeof pt);
}
#endif

// The Retry token's cases and ngtcp2's retry round, which need CHECK above.
#include "quic_token_tests.h"
#include "srv_quic_retry_tests.h"

int main(void) {
    // The client's side of the wire: one hello, built the way a QUIC
    // client builds one, carrying the transport parameters RFC 9001
    // section 8.2 requires of it.
    ch_cfg client;
    memset(&client, 0, sizeof client);
    client.alpn_protocols = alpn;
    client.alpn_count = 1;
    client.transport_params = client_params;
    client.transport_params_len = sizeof client_params;
    uint8_t pub[32];
    uint8_t random32[32];
    memset(pub, 0x11, sizeof pub);
    memset(random32, 0x22, sizeof random32);
    uint8_t hello[CH_HELLO_MAX];
    size_t hello_len =
        hs_build_client_hello(hello, sizeof hello, &client, pub, random32, 0, NULL, 0);
    CHECK(hello_len > 0);

    // The server's side.
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.buf = srv_buf;
    cfg.buf_len = sizeof srv_buf;
    cfg.alpn_protocols = alpn;
    cfg.alpn_count = 1;
    cfg.on_level_ready = level_ready;
    cfg.on_transport_params = got_params;
    memset(server_params, 0x5c, sizeof server_params);
    cfg.transport_params = server_params;
    cfg.transport_params_len = sizeof server_params;
    cfg.srv.cookie_key = cookie_key;
    cfg.srv.on_crypto_out = sink;
    provision(&cfg);

    ch_quic q;
    memset(&seen, 0, sizeof seen);
    CHECK(ch_srv_quic_init(&q, &cfg) == CH_OK);
    CHECK(ch_quic_state(&q) == CH_ST_START);

    int rc = ch_srv_quic_crypto_in(&q, CH_LEVEL_INITIAL, hello, hello_len);
    if (rc != CH_OK) {
        (void)fprintf(stderr, "crypto_in rc=%d alert=%u\n", rc, ch_quic_alert(&q));
    }
    CHECK(rc == CH_OK);

    // The client's transport parameters reached the caller unread.
    CHECK(seen.params_len == sizeof client_params);
    CHECK(seen.params != NULL && memcmp(seen.params, client_params, sizeof client_params) == 0);

    // The ServerHello went out at the Initial level and the rest of the
    // flight at the Handshake level, in that order.
    CHECK(seen.count >= 2);
    CHECK(seen.level[0] == CH_LEVEL_INITIAL);
    CHECK(seen.total[CH_LEVEL_INITIAL] > 0);
    CHECK(seen.total[CH_LEVEL_HANDSHAKE] > 0);
    for (size_t i = 1; i < seen.count && i < MAX_FRAGS; i++) {
        CHECK(seen.level[i] >= seen.level[i - 1]);
    }

    // Both Handshake directions are usable, and the application level's
    // write direction alone: the client Finished has not arrived.
    CHECK(seen.ready[CH_LEVEL_HANDSHAKE][CH_KEY_READ] == 1);
    CHECK(seen.ready[CH_LEVEL_HANDSHAKE][CH_KEY_WRITE] == 1);
    CHECK(seen.ready[CH_LEVEL_APPLICATION][CH_KEY_WRITE] == 1);
    CHECK(seen.ready[CH_LEVEL_APPLICATION][CH_KEY_READ] == 0);

    test_initial_seal_uses_the_server_labels();
    test_encrypted_extensions_max();
#ifdef CH_ROLE_BOTH
    test_both_roles_take_their_own_labels(&cfg);
#endif
    test_quic_token();
    test_ngtcp2_retry();

    if (failures == 0) {
        (void)printf("srv_quic: a ClientHello in, %zu fragments out (%zu initial, %zu handshake)\n",
                     seen.count, seen.total[CH_LEVEL_INITIAL], seen.total[CH_LEVEL_HANDSHAKE]);
    }
    return failures != 0;
}
