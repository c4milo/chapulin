// The CA build's ticket epoch rule at the two non-blocking client
// entries: ch_record_init under TRANSPORT=tcp-nonblocking and
// ch_quic_init under TRANSPORT=quic-nonblocking. A resumed session
// presents no certificate, so cfg.ticket_epoch, the stored epoch when the
// ticket arrived, is the only revocation check it gets (docs/ca.md). Each
// entry refuses a ticket below the stored epoch before it stages a byte:
// CH_EINVAL, the session failed, no alert chosen and no epoch stored
// (INV-13). bin/unit_ca holds ch_connect to the same boundary
// (test/session_cfg_tests.h), so the three client entries answer that
// ticket with one code.
//
// Built twice from this file, under -DCH_TRUST_CA:
// bin/ticket_epoch_tcp_nonblocking and bin/ticket_epoch_quic. No other
// test binary builds either transport in a CA mode.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "alert.h"
#include "cfg.h"
#include "ch_assert.h"
#include "test_random.h"
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#include "quic.h"
#else
#include "tcp_nonblocking.h"
#endif

#ifndef CH_TRUST_CA
#error "test/ticket_epoch_test.c runs the ticket epoch rule: build it with -DCH_TRUST_CA"
#endif
#if !defined(CH_TRANSPORT_TCP_NONBLOCKING) && !defined(CH_TRANSPORT_QUIC_NONBLOCKING)
#error "test/ticket_epoch_test.c runs a non-blocking entry; bin/unit_ca runs ch_connect's"
#endif

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

// The epoch the device's storage holds, and how many times a session
// wrote one back.
static uint32_t stored_epoch;
static int epoch_stores;

static int epoch_load(void *epoch_io, uint32_t *value) {
    (void)epoch_io;
    *value = stored_epoch;
    return 0;
}

static int epoch_store(void *epoch_io, uint32_t value) {
    (void)epoch_io;
    (void)value;
    epoch_stores++;
    return 0;
}

static uint8_t rxbuf[CH_MIN_RXBUF];
static const uint8_t psk[32] = {1};
static const uint8_t identity[1] = {'d'};

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
static const uint8_t params[4] = {0x04, 0x01, 0x40, 0x00}; // copied into the hello, never read
static const ch_alpn_protocol alpn = {(const uint8_t *)"h3", 2};
static ch_quic session;

static void level_ready(void *io, uint8_t level, uint8_t direction) {
    (void)io;
    (void)level;
    (void)direction;
}

static int client_init(const ch_cfg *cfg) {
    return ch_quic_init(&session, cfg);
}

static uint8_t client_state(void) {
    return ch_quic_state(&session);
}

// The bytes the entry staged: the ClientHello, at the Initial level.
static int client_out(uint8_t *out, size_t cap, size_t *out_len) {
    return ch_quic_crypto_out(&session, CH_LEVEL_INITIAL, out, cap, out_len);
}
#else
static ch_record session;

// ch_record_init requires both callbacks and calls neither, so each
// counts its calls and fails.
static int io_calls;

static int fail_send(void *io, const uint8_t *p, size_t n) {
    (void)io;
    (void)p;
    (void)n;
    io_calls++;
    return -1;
}

static int fail_recv(void *io, uint8_t *p, size_t n) {
    (void)io;
    memset(p, 0, n);
    io_calls++;
    return -1;
}

static int client_init(const ch_cfg *cfg) {
    return ch_record_init(&session, cfg);
}

static uint8_t client_state(void) {
    return ch_record_state(&session);
}

// The bytes the entry staged: the ClientHello record.
static int client_out(uint8_t *out, size_t cap, size_t *out_len) {
    return ch_record_out(&session, out, cap, out_len);
}
#endif

// A configuration that resumes a ticket issued at ticket_epoch, with the
// epoch callbacks set.
static void configure(ch_cfg *cfg, uint32_t ticket_epoch) {
    memset(cfg, 0, sizeof *cfg);
    cfg->buf = rxbuf;
    cfg->buf_len = sizeof rxbuf;
    cfg->psk = psk;
    cfg->psk_len = sizeof psk;
    cfg->psk_id = identity;
    cfg->psk_id_len = sizeof identity;
    cfg->resumption = 1;
    cfg->epoch_load = epoch_load;
    cfg->epoch_store = epoch_store;
    cfg->ticket_epoch = ticket_epoch;
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    cfg->alpn_protocols = &alpn;
    cfg->alpn_count = 1;
    cfg->transport_params = params;
    cfg->transport_params_len = sizeof params;
    cfg->quic_original_version = CH_QUIC_VERSION_1;
    // A ticket belongs to the version of the connection that received it,
    // and this one resumes a version 1 connection.
    cfg->ticket_quic_version = CH_QUIC_VERSION_1;
    cfg->on_level_ready = level_ready;
#else
    cfg->send = fail_send;
    cfg->recv = fail_recv;
#endif
}

// The stored epoch is 10. A ticket issued at 10 is the last one the rule
// takes: the entry stages its ClientHello and reports the match. A ticket
// issued at 9 is the first it refuses, because the bump to 10 retired it.
// A ticket issued at 11 still resumes: the store lost a bump, which the
// entry reports as CH_EPOCH_AHEAD rather than refuses.
static void test_ticket_epoch_boundary(void) {
    uint8_t out[sizeof session.t.tx];
    size_t out_len = 0;
    ch_cfg cfg;
    stored_epoch = 10;
    epoch_stores = 0;

    configure(&cfg, 10);
    CHECK(client_init(&cfg) == CH_OK);
    CHECK(client_state() == CH_ST_START);
    CHECK(session.t.epoch == 10 && session.t.epoch_status == CH_EPOCH_MATCHED);
    CHECK(client_out(out, sizeof out, &out_len) == CH_OK && out_len > 0);

    configure(&cfg, 9);
    CHECK(client_init(&cfg) == CH_EINVAL);
    CHECK(client_state() == CH_ST_FAILED);
    out_len = 0;
    CHECK(client_out(out, sizeof out, &out_len) == CH_EINVAL && out_len == 0);
    CHECK(ch_alert_sent(&session.t) == 0);

    configure(&cfg, 11);
    CHECK(client_init(&cfg) == CH_OK);
    CHECK(session.t.epoch == 10 && session.t.epoch_status == CH_EPOCH_AHEAD);

    // Only a handshake that authenticates a certificate writes the stored
    // epoch, and none ran here.
    CHECK(epoch_stores == 0);
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
    // The caller sends the staged bytes: no init called cfg.send or
    // cfg.recv.
    CHECK(io_calls == 0);
#endif
}

int main(void) {
    test_ticket_epoch_boundary();
    if (failures == 0) {
        (void)printf("ticket_epoch: a ticket the stored epoch retired is refused on entry with "
                     "CH_EINVAL\n");
    }
    return failures != 0;
}
