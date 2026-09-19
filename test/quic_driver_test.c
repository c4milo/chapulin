// The TRANSPORT=quic driver through its public entries: the rules
// ch_quic_init adds to the trust mode's, the staged ClientHello, a
// ServerHello delivered as CRYPTO bytes, and the level rules RFC 9001
// §4.1.3 states. No QUIC server speaks here. The ServerHello is one this
// file builds, with a key share it draws itself, so the driver installs
// the Handshake level and stops: every later message is encrypted under
// keys only a server holds. docs/quic.md, "What is still open", carries
// the interop debt that leaves.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "handshake_message.h"
#include "quic.h"
#include "quic_packet.h"
#include "test_random.h"
#include "x25519.h"

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

static uint8_t rxbuf[CH_MIN_RXBUF];
static const uint8_t params[4] = {0x04, 0x01, 0x40, 0x00}; // copied into the hello, never read
static const ch_alpn_protocol alpn = {(const uint8_t *)"h3", 2};
static uint8_t pin[256]; // an RSA-2048 modulus shape: 256 bytes, odd
static ch_quic q;

// Every level and direction cfg.on_level_ready reported, at CH_QUIC_LEVEL_BIT.
static uint8_t ready;
static void level_ready(void *io, uint8_t level, uint8_t direction) {
    (void)io;
    ready |= CH_QUIC_LEVEL_BIT(level, direction);
}

static void configure(ch_cfg *cfg) {
    memset(cfg, 0, sizeof *cfg);
    pin[sizeof pin - 1] = 1;
    cfg->buf = rxbuf;
    cfg->buf_len = sizeof rxbuf;
    cfg->server_pubkey = pin;
    cfg->server_pubkey_len = sizeof pin;
    cfg->alpn_protocols = &alpn;
    cfg->alpn_count = 1;
    cfg->transport_params = params;
    cfg->transport_params_len = sizeof params;
    cfg->on_level_ready = level_ready;
}

// One ServerHello, header included: the given suite, an empty
// legacy_session_id_echo, supported_versions naming TLS 1.3 and a
// key_share for x25519 drawn here. Returns its length.
static size_t build_server_hello(uint8_t *out, size_t cap, uint16_t suite) {
    uint8_t scalar[X25519_LEN];
    uint8_t share[X25519_LEN];
    uint8_t random[32];
    ch_rand_bytes(scalar, sizeof scalar);
    ch_rand_bytes(random, sizeof random);
    x25519_base(share, scalar);
    wbuf w;
    wb_init(&w, out, cap);
    wb_u8(&w, HS_SERVER_HELLO);
    size_t body = wb_mark(&w, 3);
    wb_u16(&w, 0x0303);
    wb_bytes(&w, random, sizeof random);
    wb_u8(&w, 0);
    wb_u16(&w, suite);
    wb_u8(&w, 0);
    size_t exts = wb_mark(&w, 2);
    wb_u16(&w, EXT_SUPPORTED_VERSIONS);
    wb_u16(&w, 2);
    wb_u16(&w, TLS13);
    wb_u16(&w, EXT_KEY_SHARE);
    wb_u16(&w, 2 + 2 + X25519_LEN);
    wb_u16(&w, CH_GROUP_X25519);
    wb_u16(&w, X25519_LEN);
    wb_bytes(&w, share, sizeof share);
    wb_patch16(&w, exts);
    wb_patch24(&w, body);
    CHECK(!w.err);
    return w.len;
}

// The rules quic.h adds to the trust mode's, refused one at a time, and
// what a refused session answers afterwards.
static void test_config_refusals(void) {
    ch_cfg cfg;
    configure(&cfg);
    cfg.alpn_count = 0; // RFC 9001 §8.1 makes ALPN mandatory
    CHECK(ch_quic_init(&q, &cfg) == CH_EINVAL && ch_quic_state(&q) == CH_ST_FAILED);
    configure(&cfg);
    cfg.transport_params_len = 0; // §8.2 makes the extension mandatory
    CHECK(ch_quic_init(&q, &cfg) == CH_EINVAL);
    configure(&cfg);
    cfg.on_level_ready = NULL;
    CHECK(ch_quic_init(&q, &cfg) == CH_EINVAL);
    configure(&cfg);
    cfg.buf_len = CH_MIN_RXBUF - 1;
    CHECK(ch_quic_init(&q, &cfg) == CH_EINVAL);
    CHECK(ch_quic_crypto_in(&q, CH_LEVEL_INITIAL, params, sizeof params) == CH_EPROTO);
    CHECK(ch_quic_error_code(&q) != 0);
}

// The hello goes out whole at Initial, the connection ID installs the
// Initial level, and a ServerHello over CRYPTO bytes installs Handshake.
static void test_driver(void) {
    ch_cfg cfg;
    uint8_t out[CH_TX_STAGE];
    uint8_t hdr[5] = {0xc0, 0, 0, 0, 1};
    uint8_t pt[8] = {0};
    uint8_t pkt[64];
    uint8_t sh[128];
    uint8_t dcid[CH_QUIC_DCID_MAX + 1] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
    size_t n = 0;
    size_t pkt_len = 0;
    configure(&cfg);
    ready = 0;
    CHECK(ch_quic_init(&q, &cfg) == CH_OK && ch_quic_state(&q) == CH_ST_START);
    // Input waits until the caller has taken the staged hello.
    CHECK(ch_quic_crypto_in(&q, CH_LEVEL_INITIAL, sh, 1) == CH_EINVAL);
    CHECK(ch_quic_crypto_out(&q, CH_LEVEL_HANDSHAKE, out, sizeof out, &n) == CH_OK && n == 0);
    CHECK(ch_quic_crypto_out(&q, CH_LEVEL_INITIAL, out, 8, &n) == CH_ECAP);
    CHECK(ch_quic_crypto_out(&q, CH_LEVEL_INITIAL, out, sizeof out, &n) == CH_OK);
    CHECK(n > 4 && out[0] == HS_CLIENT_HELLO && (((size_t)out[2] << 8) | out[3]) == n - 4);
    CHECK(ch_quic_crypto_out(&q, CH_LEVEL_INITIAL, out, sizeof out, &n) == CH_OK && n == 0);
    // No packet is protected before its level's keys are installed.
    CHECK(ch_quic_seal(&q, CH_LEVEL_INITIAL, 1, 1, hdr, sizeof hdr, pt, sizeof pt, pkt, sizeof pkt,
                       &pkt_len) == CH_EINVAL);
    CHECK(ch_quic_initial_keys(&q, dcid, sizeof dcid) == CH_EINVAL); // one past RFC 9000 §17.2
    CHECK(ch_quic_initial_keys(&q, dcid, 8) == CH_OK);
    CHECK(ch_quic_seal(&q, CH_LEVEL_INITIAL, 1, 1, hdr, sizeof hdr, pt, sizeof pt, pkt, sizeof pkt,
                       &pkt_len) == CH_OK);
    CHECK(pkt_len == sizeof hdr + sizeof pt + GCM_TAG);
    // A packet sealed under the client's Initial key does not open under
    // the server's: the tag fails, and §5.5 leaves the session live.
    uint64_t pn = 0;
    size_t pt_len = 0;
    uint8_t key_set = 0;
    CHECK(ch_quic_open(&q, CH_LEVEL_INITIAL, pkt, pkt_len, 4, 0, 0, &key_set, &pn, &pt_len) ==
          CH_QUIC_DISCARD);
    CHECK(ch_quic_state(&q) == CH_ST_START);
    // The ServerHello in two pieces: the driver waits for a whole message.
    size_t sh_len = build_server_hello(sh, sizeof sh, SUITE_CHACHA20_POLY1305_SHA256);
    CHECK(ch_quic_crypto_in(&q, CH_LEVEL_INITIAL, sh, 10) == CH_OK && ready == 0);
    CHECK(ch_quic_crypto_in(&q, CH_LEVEL_INITIAL, sh + 10, sh_len - 10) == CH_OK);
    CHECK(ready == (CH_QUIC_LEVEL_BIT(CH_LEVEL_HANDSHAKE, CH_KEY_READ) |
                    CH_QUIC_LEVEL_BIT(CH_LEVEL_HANDSHAKE, CH_KEY_WRITE)));
    CHECK(ch_quic_state(&q) == CH_ST_START);
    CHECK(ch_quic_seal(&q, CH_LEVEL_HANDSHAKE, 1, 1, hdr, sizeof hdr, pt, sizeof pt, pkt,
                       sizeof pkt, &pkt_len) == CH_OK);
    CHECK(ch_quic_seal(&q, CH_LEVEL_APPLICATION, 1, 1, hdr, sizeof hdr, pt, sizeof pt, pkt,
                       sizeof pkt, &pkt_len) == CH_EINVAL);
    // Bytes at a level this client has left: §4.1.3's PROTOCOL_VIOLATION.
    CHECK(ch_quic_crypto_in(&q, CH_LEVEL_INITIAL, sh, sh_len) == CH_EPROTO);
    CHECK(ch_quic_state(&q) == CH_ST_FAILED && ch_quic_error_code(&q) == 0x0a);
    CHECK(ch_quic_alert(&q) == ALERT_UNEXPECTED_MESSAGE);
    ch_quic_close(&q);
    CHECK(ch_quic_state(&q) == CH_ST_CLOSED && ch_quic_error_code(&q) == 0);
}

// A ServerHello naming a suite this client never offered kills the
// session, and RFC 9001 §4.8 carries the alert as 0x0100 plus its value.
static void test_server_hello_refused(void) {
    ch_cfg cfg;
    uint8_t out[CH_TX_STAGE];
    uint8_t sh[128];
    size_t n = 0;
    configure(&cfg);
    CHECK(ch_quic_init(&q, &cfg) == CH_OK);
    CHECK(ch_quic_crypto_out(&q, CH_LEVEL_INITIAL, out, sizeof out, &n) == CH_OK && n > 0);
    size_t sh_len = build_server_hello(sh, sizeof sh, 0x1301); // TLS_AES_128_GCM_SHA256
    CHECK(ch_quic_crypto_in(&q, CH_LEVEL_INITIAL, sh, sh_len) == CH_EPROTO);
    CHECK(ch_quic_state(&q) == CH_ST_FAILED && ch_quic_alert(&q) == ALERT_ILLEGAL_PARAMETER);
    CHECK(ch_quic_error_code(&q) == 0x0100 + ALERT_ILLEGAL_PARAMETER);
}

int main(void) {
    test_config_refusals();
    test_driver();
    test_server_hello_refused();
    if (failures == 0) {
        (void)printf("quic_driver: the driver stages, installs and refuses as quic.h states\n");
    }
    return failures != 0;
}
