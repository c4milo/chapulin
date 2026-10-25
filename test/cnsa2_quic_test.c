// The PROFILE=cnsa2 client over TRANSPORT=quic-nonblocking
// (docs/decisions.md 151): ch_quic_init's refusal of a pin, and two whole
// handshakes against the mock server of test/cnsa2_mock.h, carried as
// CRYPTO bytes. The first runs under the external PSK and keeps the
// ticket the mock issues, and the second resumes it. Each one checks the
// binder and the client Finished, and the session reports the profile's
// group and suite. test/cnsa2_test.c runs the same mock over records.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "buf.h"
#include "ch_assert.h"
#include "handshake_message.h"
#include "keysched.h"
#include "mlkem.h"
#include "quic.h"
#include "test_random.h"
#include "test_widemul.h"
#include "transcript.h"

#ifndef CH_PROFILE_CNSA2
#error "test/cnsa2_quic_test.c checks the PROFILE=cnsa2 client: build it with -DCH_PROFILE_CNSA2"
#endif

static int failures = 0;
#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                  \
        }                                                                                          \
    } while (0)

noreturn void ch_assert_fail(const char *cond, const char *file, int line) {
    (void)fprintf(stderr, "ASSERT %s:%d: %s\n", file, line, cond);
    abort();
}

#include "hello_exts.h"

#include "cnsa2_mock.h"

static uint8_t rxbuf[CH_MIN_RXBUF];
static const uint8_t params[4] = {0x04, 0x01, 0x40, 0x00}; // copied into the hello, never read
static const ch_alpn_protocol alpn = {(const uint8_t *)"h3", 2};
static ch_quic q;
static ch_saved_ticket saved;
static int tickets;

// The EncryptedExtensions block: ALPN selecting h3, and the server's
// transport parameters, which RFC 9001 §8.1 and §8.2 require.
static const uint8_t ee_exts[] = {0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '3',
                                  0x00, 0x39, 0x00, 0x04, 0x04, 0x01, 0x40, 0x00};

// Every level and direction cfg.on_level_ready reported, at CH_QUIC_LEVEL_BIT.
static uint8_t ready;
static void level_ready(void *io, uint8_t level, uint8_t direction) {
    (void)io;
    ready |= CH_QUIC_LEVEL_BIT(level, direction);
}

static void on_ticket(void *io, const ch_ticket *ticket) {
    (void)io;
    tickets++;
    CHECK(ticket->psk_len == SHA384_LEN);
    CHECK(ch_ticket_save(&saved, ticket) == 0);
}

static void configure(ch_cfg *cfg) {
    memset(cfg, 0, sizeof *cfg);
    cfg->buf = rxbuf;
    cfg->buf_len = sizeof rxbuf;
    cfg->psk = external_psk;
    cfg->psk_len = sizeof external_psk;
    cfg->psk_id = external_id;
    cfg->psk_id_len = sizeof external_id;
    cfg->alpn_protocols = &alpn;
    cfg->alpn_count = 1;
    cfg->transport_params = params;
    cfg->transport_params_len = sizeof params;
    cfg->quic_original_version = CH_QUIC_VERSION_1;
    cfg->on_level_ready = level_ready;
    cfg->on_ticket = on_ticket;
}

// A pin beside the PSK, or in its place, is refused with nothing staged.
// The pin has an RSA-2048 modulus's shape, 256 bytes and odd, so every
// other build takes it.
static void test_cnsa2_quic_cfg(void) {
    static uint8_t pin[256];
    pin[0] = 0xc1;
    pin[sizeof pin - 1] = 1;
    ch_cfg cfg;
    configure(&cfg);
    CHECK(ch_quic_init(&q, &cfg) == CH_OK && q.tx_len > 0);
    cfg.server_pubkey = pin;
    cfg.server_pubkey_len = sizeof pin;
    CHECK(ch_quic_init(&q, &cfg) == CH_EINVAL && q.tx_len == 0);
    cfg.psk = NULL;
    cfg.psk_len = 0;
    cfg.psk_id = NULL;
    cfg.psk_id_len = 0;
    CHECK(ch_quic_init(&q, &cfg) == CH_EINVAL && q.tx_len == 0);
}

// One handshake: the hello out at Initial, the ServerHello in at Initial,
// the flight in at Handshake, the client Finished out at Handshake, and
// the ticket in at Application.
static void run_handshake(int resume) {
    static cnsa2_mock m;
    memset(&m, 0, sizeof m);
    ch_cfg cfg;
    configure(&cfg);
    if (resume) {
        cfg.ticket = &saved;
    }
    ready = 0;
    tickets = 0;
    CHECK(ch_quic_init(&q, &cfg) == CH_OK);
    CHECK(ch_quic_crypto_out(&q, CH_LEVEL_INITIAL, m.hello, sizeof m.hello, &m.hello_len) == CH_OK);
    // The QUIC hello opens with the ALPN offer RFC 9001 §8.1 requires,
    // offers no signature scheme and ends in the pre_shared_key.
    CHECK(hello_first_ext(m.hello, m.hello_len) == EXT_ALPN);
    CHECK(hello_sigalgs(m.hello, m.hello_len, NULL, 0) == -1);
    int count = 0;
    CHECK(hello_ext_index(m.hello, m.hello_len, EXT_PRE_SHARED_KEY, &count) == count - 1);
    static uint8_t msg[128 + MLKEM_CT_LEN];
    size_t n = mock_server_hello(&m, msg, sizeof msg);
    CHECK(m.binder_ok && m.resumed == resume);
    CHECK(ch_quic_crypto_in(&q, CH_LEVEL_INITIAL, msg, n) == CH_OK);
    CHECK(ready == (CH_QUIC_LEVEL_BIT(CH_LEVEL_HANDSHAKE, CH_KEY_READ) |
                    CH_QUIC_LEVEL_BIT(CH_LEVEL_HANDSHAKE, CH_KEY_WRITE)));
    CHECK(q.t.group == CH_GROUP_MLKEM1024 && q.t.suite == SUITE_AES_256_GCM_SHA384);
    n = mock_server_flight(&m, ee_exts, sizeof ee_exts, msg, sizeof msg);
    CHECK(ch_quic_crypto_in(&q, CH_LEVEL_HANDSHAKE, msg, n) == CH_OK);
    CHECK(ch_quic_state(&q) == CH_ST_START);
    CHECK(ch_quic_crypto_out(&q, CH_LEVEL_HANDSHAKE, msg, sizeof msg, &n) == CH_OK);
    CHECK(ch_quic_state(&q) == CH_ST_CONNECTED);
    mock_client_finished(&m, msg, n);
    CHECK(m.client_finished_ok);
    CHECK(q.t.psk_selected == 1);
    n = mock_ticket(msg, sizeof msg);
    CHECK(ch_quic_crypto_in(&q, CH_LEVEL_APPLICATION, msg, n) == CH_OK);
    CHECK(tickets == 1);
    ch_quic_close(&q);
}

int main(void) {
    test_cnsa2_quic_cfg();
    run_handshake(0);
    run_handshake(1);
    if (failures > 0) {
        (void)fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    (void)printf("cnsa2_quic_test: all checks passed\n");
    return 0;
}
