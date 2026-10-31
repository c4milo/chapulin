// Proves: ch_srv_quic_init, ch_srv_quic_crypto_in, ch_srv_quic_retry_tag
// and the step table under them (srv_quic.c), with quic_fail.c's failure
// path and the QUIC arm of handshake_record.c, are memory safe and free of
// UB over an unconstrained ch_cfg, saved state, level and caller bytes.
// And that the driver keeps what srv_quic.h states:
// - init answers CH_OK with the session at its first step and the
//   Initial level, or CH_EINVAL with a dead session (INV-13);
// - a ClientHello with no quic_transport_parameters is refused with
//   missing_extension, and a version cfg.srv.choose_version answers that
//   quic_version_derived refuses is CH_EIO with internal_error, with the
//   negotiated version unchanged;
// - a step after the handshake fails with unexpected_message, and a
//   second HelloRetryRequest is unreachable: a retry hello step never
//   returns to it;
// - the client Finished step leaves the session connected at the 1-RTT
//   level, with the handshake state wiped and its back pointer written
//   again (INV-17);
// - a level is announced to cfg.on_level_ready only after its bit is set,
//   and 1-RTT read only at the client Finished;
// - every failure of ch_srv_quic_crypto_in but CH_EINVAL leaves the
//   session dead, with nothing unread and no read key or traffic secret
//   (INV-13, INV-17).
//
// What is real and what is a stub. srv_quic.c, quic_fail.c,
// handshake_record.c and ct.c are real. The fifteen handlers are the
// contract stubs proof/srv_flight_stubs.h states, and srv_flight proves
// them. quic_keys.c's three derivations and quic_retry_tag are stubs, as
// in proof/quic_step_harness.c, and ct_wipe writes its zeros with one
// memset.
//
// Bounds. CH_PROOF_RXBUF is 12, the value handshake_record's harness
// uses. srv_config_ok's stub promises a buffer of CH_MIN_RXBUF bytes, so
// init takes init_buf, which it stores and never reads. drive.0 is 5:
// each pass past the first runs a step, a step consumes at least four
// bytes, and twelve bytes hold at most three messages.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include <string.h>

#include "handshake_message.h"
#include "handshake_record.h"
#include "quic.h"
#include "quic_keys.h"
#include "srv_flight.h"
#include "srv_quic.h"

#ifndef CH_PROOF_RXBUF
#define CH_PROOF_RXBUF 12
#endif

int nondet_int(void);
uint16_t nondet_u16(void);
uint64_t nondet_u64(void);

#include "srv_flight_stubs.h"

static ch_quic q;
static ch_cfg cfg;
static uint8_t buf[CH_PROOF_RXBUF];
static uint8_t init_buf[CH_MIN_RXBUF];

void quic_keys_init(uint32_t cpu, quic_keys *k, uint32_t version,
                    const uint8_t secret[SHA256_LEN]) {
    (void)cpu;
    __CPROVER_assert(__CPROVER_w_ok(k, sizeof *k), "keys: set writable");
    __CPROVER_assert(version == q.t.quic_negotiated_version, "keys: the negotiated version");
    __CPROVER_assert(__CPROVER_r_ok(secret, SHA256_LEN), "keys: secret readable");
    fill_nondet(k->key, sizeof k->key);
    fill_nondet(k->iv, sizeof k->iv);
}

void quic_hp_key_init(uint32_t cpu, quic_hp_key *h, uint32_t version,
                      const uint8_t secret[SHA256_LEN]) {
    (void)cpu;
    __CPROVER_assert(__CPROVER_w_ok(h, sizeof *h), "keys: header key writable");
    __CPROVER_assert(version == q.t.quic_negotiated_version, "keys: the negotiated version");
    __CPROVER_assert(__CPROVER_r_ok(secret, SHA256_LEN), "keys: secret readable");
    fill_nondet(h->key, sizeof h->key);
}

void quic_keys_update(uint32_t cpu, uint8_t secret[SHA256_LEN], quic_keys *k, uint32_t version) {
    (void)cpu;
    __CPROVER_assert(__CPROVER_w_ok(secret, SHA256_LEN), "update: secret writable");
    __CPROVER_assert(__CPROVER_w_ok(k, sizeof *k), "update: set writable");
    __CPROVER_assert(version == q.t.quic_negotiated_version, "update: the negotiated version");
    fill_nondet(secret, SHA256_LEN);
    fill_nondet(k->key, sizeof k->key);
    fill_nondet(k->iv, sizeof k->iv);
}

// quic_retry.h: the tag over n bytes of pseudo-packet, or a refusal.
int quic_retry_tag(uint32_t version, const uint8_t *pseudo, size_t n, uint8_t tag[GCM_TAG]) {
    (void)version;
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(pseudo, n), "retry tag: packet readable");
    __CPROVER_assert(__CPROVER_w_ok(tag, GCM_TAG), "retry tag: tag writable");
    fill_nondet(tag, GCM_TAG);
    return nondet_int();
}

// ct_wipe's contract (ct.h), one memset, as in
// proof/srv_tcp_nonblocking_harness.c; ct proves the body.
void ct_wipe(void *p, size_t n) {
    __CPROVER_assert(n == 0 || __CPROVER_w_ok(p, n), "wipe: the bytes are writable");
    if (n != 0) {
        memset(p, 0, n);
    }
}

#include "quic_fail.c"
#include "srv_quic.c"

// cfg.on_level_ready: the bit is set before the caller hears of a level.
static int app_read_announced;
static void level_ready(void *io, uint8_t level, uint8_t direction) {
    (void)io;
    __CPROVER_assert(level == CH_LEVEL_HANDSHAKE || level == CH_LEVEL_APPLICATION,
                     "ready: the Handshake or the 1-RTT level");
    __CPROVER_assert(direction == CH_KEY_READ || direction == CH_KEY_WRITE,
                     "ready: one direction per call");
    __CPROVER_assert((q.levels_ready & CH_QUIC_LEVEL_BIT(level, direction)) != 0,
                     "ready: the bit is set before the caller hears about it");
    if (level == CH_LEVEL_APPLICATION && direction == CH_KEY_READ) {
        __CPROVER_assert(q.t.state == CH_ST_CONNECTED,
                         "ready: 1-RTT read once the client Finished verified");
        app_read_announced++;
    }
}

static int crypto_out(void *io, uint8_t level, const uint8_t *p, size_t n) {
    (void)io;
    (void)level;
    (void)p;
    (void)n;
    return 0;
}

static void transport_params(void *io, const uint8_t *body, size_t n) {
    (void)io;
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(body, n), "params: body readable");
}

static uint32_t chosen;
static uint32_t choose(void *io) {
    (void)io;
    chosen = nondet_u32();
    return chosen;
}

// Whether n bytes are all zero, as one answer.
static int zero_bytes(const void *p, size_t n) {
    const uint8_t *b = p;
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        acc |= b[i];
    }
    return acc == 0;
}

// The saved state any call can meet, every field the driver reads
// havocked.
static void havoc_session(void) {
    memset(&q, 0, sizeof q);
    q.t.cfg = cfg;
    q.t.cfg.buf = buf;
    q.t.cfg.buf_len = sizeof buf;
    q.hs.t = &q.t;
    q.endpoint = CH_QUIC_ENDPOINT_SERVER;
    q.step = nondet_u8();
    q.rx_level = nondet_u8();
    q.levels_ready = nondet_u8();
    q.hs.alert = nondet_u8();
    q.hs.level = nondet_u8();
    fill_nondet(buf, sizeof buf);
    fill_nondet(q.t.rd_secret, sizeof q.t.rd_secret);
    fill_nondet(q.t.wr_secret, sizeof q.t.wr_secret);
    fill_nondet(q.handshake_rx.key, sizeof q.handshake_rx.key);
    q.t.quic_negotiated_version = nondet_u32();
    uint8_t state = nondet_u8();
    __CPROVER_assume(state <= CH_ST_FAILED);
    q.t.state = state;
    size_t off = nondet_size_t();
    size_t len = nondet_size_t();
    __CPROVER_assume(off <= len && len <= sizeof buf);
    q.t.pt_off = off;
    q.t.pt_len = len;
}

static void prove_init(void) {
    int rc = ch_srv_quic_init(&q, &cfg);
    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL, "init answers one of its two codes");
    if (rc != CH_OK) {
        __CPROVER_assert(q.t.state == CH_ST_FAILED && q.levels_ready == 0,
                         "a refused configuration leaves it dead");
        return;
    }
    __CPROVER_assert(q.t.state == CH_ST_START && q.step == SQ_STEP_AWAIT_CLIENT_HELLO &&
                         q.rx_level == CH_LEVEL_INITIAL && q.hs.t == &q.t,
                     "a prepared session waits at the first step and the Initial level");
    __CPROVER_assert(q.endpoint == CH_QUIC_ENDPOINT_SERVER &&
                         q.t.quic_negotiated_version == cfg.quic_original_version,
                     "as a server, in the client's version");
}

static void prove_advance(void) {
    havoc_session();
    __CPROVER_assume(q.t.pt_len - q.t.pt_off >= 4); // what drive checked
    __CPROVER_assume(quic_version_derived(q.t.quic_negotiated_version));
    uint8_t was_step = q.step;
    uint32_t was_version = q.t.quic_negotiated_version;
    chosen = 0;
    hello_params = -1;
    int rc = advance(&q);
    if (was_step == SQ_STEP_AWAIT_CLIENT_HELLO && hello_params == 0) {
        __CPROVER_assert(rc == CH_EPROTO && q.hs.alert == ALERT_MISSING_EXTENSION,
                         "a first hello without transport parameters is refused");
    }
    __CPROVER_assert(q.t.pt_off <= q.t.pt_len && q.t.pt_len <= q.t.cfg.buf_len,
                     "a step leaves the window inside the buffer");
    if (was_step > SQ_STEP_AWAIT_CLIENT_FINISHED) {
        __CPROVER_assert(rc == CH_EPROTO && q.hs.alert == ALERT_UNEXPECTED_MESSAGE,
                         "no step runs after the handshake");
    }
    if (chosen != 0 && !quic_version_derived(chosen)) {
        __CPROVER_assert(rc == CH_EIO && q.hs.alert == ALERT_INTERNAL_ERROR &&
                             q.t.quic_negotiated_version == was_version,
                         "a version this build does not derive is the caller's failure");
    }
    if (rc != CH_OK) {
        return;
    }
    if (was_step == SQ_STEP_AWAIT_CLIENT_HELLO) {
        __CPROVER_assert(q.step == SQ_STEP_AWAIT_RETRY_HELLO ||
                             q.step == SQ_STEP_AWAIT_CLIENT_FINISHED,
                         "the first hello asks for a retry or answers with the flight");
    }
    if (was_step == SQ_STEP_AWAIT_RETRY_HELLO) {
        __CPROVER_assert(q.step == SQ_STEP_AWAIT_CLIENT_FINISHED, "a second retry is unreachable");
    }
    if (q.step == SQ_STEP_AWAIT_CLIENT_FINISHED) {
        __CPROVER_assert(q.rx_level == CH_LEVEL_HANDSHAKE, "the client Finished is read there");
    }
    if (was_step == SQ_STEP_AWAIT_CLIENT_FINISHED) {
        __CPROVER_assert(q.step == SQ_STEP_COMPLETE && q.t.state == CH_ST_CONNECTED &&
                             q.rx_level == CH_LEVEL_APPLICATION,
                         "the client Finished ends the handshake");
        __CPROVER_assert(q.hs.t == &q.t && zero_bytes(q.hs.c_hs, sizeof q.hs.c_hs) &&
                             zero_bytes(q.hs.s_hs, sizeof q.hs.s_hs),
                         "with the handshake state wiped and the back pointer set");
    }
}

static void prove_crypto_in(void) {
    havoc_session();
    fill_nondet(q.app_hp_rx.key, sizeof q.app_hp_rx.key);
    uint8_t in[CH_PROOF_RXBUF];
    fill_nondet(in, sizeof in);
    size_t n = nondet_size_t();
    __CPROVER_assume(n <= sizeof in);
    uint8_t level = nondet_u8();
    int was_dead = session_dead(&q);
    int rc = ch_srv_quic_crypto_in(&q, level, in, n);
    __CPROVER_assert(q.t.pt_off <= q.t.pt_len && q.t.pt_len <= q.t.cfg.buf_len,
                     "the window stays inside the buffer");
    if (was_dead) {
        __CPROVER_assert(rc == CH_EPROTO, "a dead session refuses the call");
    } else if (level > CH_LEVEL_APPLICATION) {
        __CPROVER_assert(rc == CH_EINVAL, "a level QUIC does not name is refused");
    } else if (rc != CH_OK && rc != CH_EINVAL) {
        __CPROVER_assert(q.t.state == CH_ST_FAILED && q.t.pt_off == 0 && q.t.pt_len == 0,
                         "a failure leaves the session dead with nothing unread");
        __CPROVER_assert(zero_bytes(q.t.rd_secret, sizeof q.t.rd_secret) &&
                             zero_bytes(q.t.wr_secret, sizeof q.t.wr_secret) &&
                             zero_bytes(&q.handshake_rx, sizeof q.handshake_rx) &&
                             zero_bytes(&q.app_hp_rx, sizeof q.app_hp_rx),
                         "and no read key or traffic secret (INV-17)");
    }
}

int main(void) {
    memset(&cfg, 0, sizeof cfg);
    cfg.buf = init_buf;
    cfg.buf_len = sizeof init_buf;
    cfg.on_level_ready = level_ready;
    cfg.srv.on_crypto_out = crypto_out;
    cfg.on_transport_params = (nondet_u8() & 1) ? transport_params : NULL;
    cfg.srv.choose_version = (nondet_u8() & 1) ? choose : NULL;
    cfg.quic_original_version = nondet_u32();
    prove_init();
    prove_advance();
    prove_crypto_in();
    uint8_t pseudo[4];
    uint8_t tag[CH_QUIC_RETRY_TAG_LEN];
    (void)ch_srv_quic_retry_tag(nondet_u32(), pseudo, sizeof pseudo, tag);
    return 0;
}
