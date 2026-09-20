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
// What it does not check: the client Finished, which needs a real client's
// transcript and key schedule. The steps up to it are what this covers.
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
static const uint8_t alpn_h3[] = {'h', '3'};
static const ch_alpn_protocol alpn[1] = {
    {alpn_h3, sizeof alpn_h3}
};

static uint8_t srv_buf[CH_MIN_RXBUF];

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
    cfg.transport_params = client_params;
    cfg.transport_params_len = sizeof client_params;
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

    if (failures == 0) {
        (void)printf("srv_quic: a ClientHello in, %zu fragments out (%zu initial, %zu handshake)\n",
                     seen.count, seen.total[CH_LEVEL_INITIAL], seen.total[CH_LEVEL_HANDSHAKE]);
    }
    return failures != 0;
}
