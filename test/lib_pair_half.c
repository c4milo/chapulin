// One half of the image test/lib-pair-check.sh links from two packaged
// objects of different transports. It compiles under the defines of one
// object, the way a program that uses two transports compiles each one's
// calls in a translation unit of its own: the two objects' headers
// disagree about ch_cfg and ch_tls, so no translation unit reads both.
//
// Its one function is named for the transport (lib_pair.h) and runs up
// to four steps against the object:
//
//   1. ch_build_matches(&ch_build), which reads this transport's record;
//   2. ch_srv_check, where the object carries a server;
//   3. ch_pubkey_from_pem, where the object is a CA mode;
//   4. one session: a client builds its ClientHello, and a server-only
//      object prepares a session to read one.
//
// Steps 1 to 3 call names that build.h, srv.h and x509_ca.h map to this
// transport's symbol names (docs/decisions.md 61). A step that reached
// the other object would read a record or a ch_cfg of another layout.
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "build.h"
#include "cfg.h"
#include "lib_pair.h"
#include "session.h"
#include "tls.h"
#ifdef CH_ROLE_SERVER
#include "p256_sign_vectors.h"
#include "srv.h"
#include "srv_quic.h"
#include "srv_rec.h"
#endif
#ifdef CH_TRUST_CA
#include "pem.h"
#include "pem_armor.h"
#include "x509_ca.h"
#include "x509_vectors.h"
#endif

#ifdef CH_TRANSPORT_QUIC
#define LIB_PAIR_HALF lib_pair_quic
#define LIB_PAIR_TRANSPORT "quic"
#elif defined(CH_TRANSPORT_RECORD)
#define LIB_PAIR_HALF lib_pair_record
#define LIB_PAIR_TRANSPORT "record"
#else
#define LIB_PAIR_HALF lib_pair_tls
#define LIB_PAIR_TRANSPORT "tls"
#endif

// A server-only object judges no peer certificate, so it has a server
// to start and no client.
#if defined(CH_ROLE_SERVER) && !defined(CH_ROLE_BOTH)
#define LIB_PAIR_SERVER_ONLY
#endif

static int failed(const char *step) {
    (void)fprintf(stderr, "lib-pair: the %s half: %s\n", LIB_PAIR_TRANSPORT, step);
    return 1;
}

// The receive buffer every session here takes, at the floor this
// object's own defines set.
static uint8_t rxbuf[CH_MIN_RXBUF];

#ifdef CH_TRANSPORT_QUIC
// RFC 9001 requires transport parameters (section 8.2) and an ALPN
// protocol (section 8.1) in every QUIC handshake.
static const uint8_t params[4] = {0x01, 0x02, 0x03, 0x04};
static const uint8_t alpn_h3[2] = {'h', '3'};
static const ch_alpn_protocol alpn[1] = {
    {alpn_h3, sizeof alpn_h3}
};

static void level_ready(void *io, uint8_t level, uint8_t direction) {
    (void)io;
    (void)level;
    (void)direction;
}
#else
// The first byte the session sent, which for a TLS record is its content
// type. A handshake record is type 22 (RFC 9846 section 5.1).
#define LIB_PAIR_HANDSHAKE_RECORD 22
static uint8_t first_sent;

static int keep_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    if (first_sent == 0 && n > 0) {
        first_sent = p[0];
    }
    return 0;
}

// No peer answers, so every read fails, and a blocking handshake stops
// at its first read with CH_EIO.
static int fail_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    memset(p, 0, n);
    return -1;
}
#endif

// The fields every session here sets, whatever its role.
static void base_config(ch_cfg *cfg) {
    memset(cfg, 0, sizeof *cfg);
    cfg->buf = rxbuf;
    cfg->buf_len = sizeof rxbuf;
#ifdef CH_TRANSPORT_QUIC
    cfg->transport_params = params;
    cfg->transport_params_len = sizeof params;
    cfg->on_level_ready = level_ready;
    cfg->alpn_protocols = alpn;
    cfg->alpn_count = 1;
#else
    cfg->send = keep_send;
    cfg->recv = fail_recv;
#endif
}

#ifdef CH_ROLE_SERVER
// One certificate the chain names. A server object links no X.509
// reader, so no step here reads a byte of it.
static const uint8_t cert_der[4] = {0x30, 0x02, 0x05, 0x00};
static const ch_cert chain[1] = {
    {cert_der, sizeof cert_der}
};

// A P-256 identity. ECDSA signs under RFC 6979's deterministic nonce, so
// ch_srv_check draws nothing from ch_rand_bytes here.
static void provision(ch_cfg *cfg) {
    cfg->srv.ecdsa_p256.chain = chain;
    cfg->srv.ecdsa_p256.chain_count = 1;
    cfg->srv.ecdsa_p256.priv = p256_sign_vectors[0].priv;
    cfg->srv.ecdsa_p256.priv_len = sizeof p256_sign_vectors[0].priv;
    cfg->srv.ecdsa_p256.pub = p256_sign_vectors[0].pub;
    cfg->srv.ecdsa_p256.pub_len = sizeof p256_sign_vectors[0].pub;
}

static int check_identity(void) {
    ch_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    provision(&cfg);
    return ch_srv_check(&cfg) == CH_OK ? 0 : failed("ch_srv_check refused a P-256 identity");
}
#endif

#ifdef LIB_PAIR_SERVER_ONLY
static const uint8_t cookie_key[SHA256_LEN] = {7};

#ifdef CH_TRANSPORT_QUIC
static int take_crypto(void *io, uint8_t level, const uint8_t *p, size_t n) {
    (void)io;
    (void)level;
    (void)p;
    (void)n;
    return 0;
}

static ch_quic server;

static int start_server(ch_cfg *cfg) {
    cfg->srv.on_crypto_out = take_crypto;
    int rc = ch_srv_quic_init(&server, cfg);
    uint8_t state = ch_quic_state(&server);
    ch_quic_close(&server);
    return rc == CH_OK && state == CH_ST_START ? 0 : failed("ch_srv_quic_init refused a server");
}
#elif defined(CH_TRANSPORT_RECORD)
static int take_record(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    return 0;
}

static ch_record server;

static int start_server(ch_cfg *cfg) {
    cfg->srv.on_record_out = take_record;
    int rc = ch_srv_record_init(&server, cfg);
    uint8_t state = ch_record_state(&server);
    ch_record_close(&server);
    return rc == CH_OK && state == CH_ST_START ? 0 : failed("ch_srv_record_init refused a server");
}
#else
#error "no pair in test/lib-pair-check.sh links a TRANSPORT=tls server"
#endif

static int start_session(void) {
    ch_cfg cfg;
    base_config(&cfg);
    cfg.srv.cookie_key = cookie_key;
    provision(&cfg);
    return start_server(&cfg);
}
#else
#ifdef CH_TRUST_WEBPKI
// An anchor, a hostname and a clock, the configuration both transports
// take. The anchor's bytes are placeholders: the init calls check only
// that each field is set, and no certificate arrives here.
static const uint8_t anchor_name[2] = {0x30, 0x00};
static const uint8_t anchor_spki[2] = {0x30, 0x00};
static const ch_trust_anchor anchors[1] = {
    {anchor_name, sizeof anchor_name, anchor_spki, sizeof anchor_spki}
};
static const uint8_t hostname[11] = {'d', 'n', 's', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'};
#else
// A PSK, which every raw and CA mode takes.
static const uint8_t psk[SHA256_LEN] = {0x0b};
static const uint8_t psk_id[4] = {'p', 'a', 'i', 'r'};
#endif

static void client_config(ch_cfg *cfg) {
    base_config(cfg);
#ifdef CH_TRUST_WEBPKI
    cfg->anchors = anchors;
    cfg->anchor_count = 1;
    cfg->hostname = hostname;
    cfg->hostname_len = sizeof hostname;
    cfg->now_seconds = 1789000000U;
#else
    cfg->psk = psk;
    cfg->psk_len = sizeof psk;
    cfg->psk_id = psk_id;
    cfg->psk_id_len = sizeof psk_id;
#endif
}

#if defined(CH_TRANSPORT_QUIC) || defined(CH_TRANSPORT_RECORD)
// The client's first flight, which it stages in ch_tls.tx.
static uint8_t flight[CH_TX_STAGE];
#endif

#ifdef CH_TRANSPORT_QUIC
// A ClientHello is handshake message type 1 (RFC 9846 section 4).
#define LIB_PAIR_CLIENT_HELLO 1
static ch_quic client;

static int start_session(void) {
    ch_cfg cfg;
    client_config(&cfg);
    if (ch_quic_init(&client, &cfg) != CH_OK) {
        return failed("ch_quic_init refused a client");
    }
    size_t n = 0;
    int rc = ch_quic_crypto_out(&client, CH_LEVEL_INITIAL, flight, sizeof flight, &n);
    ch_quic_close(&client);
    return rc == CH_OK && n > 0 && flight[0] == LIB_PAIR_CLIENT_HELLO
               ? 0
               : failed("ch_quic_crypto_out handed out no ClientHello");
}
#elif defined(CH_TRANSPORT_RECORD)
static ch_record client;

static int start_session(void) {
    ch_cfg cfg;
    client_config(&cfg);
    if (ch_record_init(&client, &cfg) != CH_OK) {
        return failed("ch_record_init refused a client");
    }
    size_t n = 0;
    int rc = ch_record_out(&client, flight, sizeof flight, &n);
    ch_record_close(&client);
    return rc == CH_OK && n > 0 && flight[0] == LIB_PAIR_HANDSHAKE_RECORD
               ? 0
               : failed("ch_record_out handed out no handshake record");
}
#else
static ch_tls client;

// ch_connect sends the ClientHello and then stops at its first read.
static int start_session(void) {
    ch_cfg cfg;
    client_config(&cfg);
    first_sent = 0;
    int rc = ch_connect(&client, &cfg);
    ch_close(&client);
    return rc == CH_EIO && first_sent == LIB_PAIR_HANDSHAKE_RECORD
               ? 0
               : failed("ch_connect sent no handshake record before its first read");
}
#endif
#endif

#ifdef CH_TRUST_CA
// The intermediate CA certificate of the build's pinned algorithm, the
// one test/hpp_test.cpp provisions from: the key it yields is the length
// ch_cfg.server_pubkey takes in this build.
#ifdef CH_PIN_ECDSA
#define LIB_PAIR_CA certv_int_p256
#define LIB_PAIR_CA_KEY_LEN 64
#else
#define LIB_PAIR_CA certv_int_rsa
#define LIB_PAIR_CA_KEY_LEN 384
#endif
static uint8_t pem[CH_PEM_MAX];
static uint8_t der[CH_X509_MAX];
static uint8_t key[CH_X509_KEY_MAX];

static int provision_ca(void) {
    size_t pem_len = pem_armor(LIB_PAIR_CA, sizeof LIB_PAIR_CA, 64, "\n", pem);
    size_t key_len = 0;
    int rc = ch_pubkey_from_pem(pem, pem_len, der, key, &key_len);
    return rc == CH_OK && key_len == LIB_PAIR_CA_KEY_LEN
               ? 0
               : failed("ch_pubkey_from_pem refused a CA certificate");
}
#endif

int LIB_PAIR_HALF(void) {
    if (!ch_build_matches(&ch_build)) {
        return failed("ch_build_matches read a record that is not this object's");
    }
#ifdef CH_ROLE_SERVER
    if (check_identity() != 0) {
        return 1;
    }
#endif
#ifdef CH_TRUST_CA
    if (provision_ca() != 0) {
        return 1;
    }
#endif
    return start_session();
}
