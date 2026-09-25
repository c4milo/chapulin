// Proves: under TRUST=webpki and TRANSPORT=quic-nonblocking,
// quic_config_ok is memory-safe and UB-free over any configuration, and
// its CH_OK keeps the contract quic.h and webpki_cfg.h state. quic_config.c
// and webpki_cfg.c are real, as separate translation units on the launch
// line, because each holds its own static alpn_ok. So one formula covers
// the rules ch_quic_init applies and the webpki_cfg_ok rules ch_connect
// applies over TCP, which the QUIC object now calls for SPKI pins
// (docs/decisions.md 64).
//
// The properties, over unconstrained inputs: every pointer field NULL or
// set, and every count and length any size_t. A set pointer holds its
// length, which cfg.h makes the caller's requirement, except where a
// count is capped: anchor_count, spki_pin_count and alpn_count are
// unconstrained beside arrays that hold CH_WEBPKI_ANCHOR_MAX, CH_SPKI_PIN_MAX
// and CH_ALPN_MAX entries, so the formula shows the rules read no entry
// past the cap before they refuse the count. Memory safety and absence of
// UB, which the automatic checks discharge. And the verdict: CH_OK or
// CH_EINVAL, and CH_OK only for a configuration that holds 0 to
// CH_SPKI_PIN_MAX pins with a list exactly when it holds a count; either
// pins alone, with no anchor, no clock read and a hostname unset or of
// the checked shape, or 1 to CH_WEBPKI_ANCHOR_MAX anchors with a
// hostname and a clock; no pin slot; PSK fields webpki_resumption_ok
// took; 1 to CH_ALPN_MAX protocols; transport parameters of 1 to
// CH_TRANSPORT_PARAMS_MAX bytes; on_level_ready; the buffer floor; and
// no epoch callback.
//
// Three callees are contract stubs, each proven by its own harness.
// webpki_hostname_ok asserts it may read the name and answers 1 only for
// 1 to CH_HOSTNAME_MAX bytes (webpki_name). webpki_resumption_ok asserts
// the rules webpki_ticket.h requires before it runs, the hostname, anchor
// and pin rules, which is what makes webpki_cfg_ok's order a property
// here, and answers 1 only for the PSK shapes webpki_ticket.h states
// (webpki_ticket). ct_memeq asserts it may read both names and answers
// 0 or 1 (ct). The real ct_memeq, compared byte by byte across every pair
// of eight 32-byte names, took the formula from 2 s and 72 MB to 141 s
// and 2.7 GB and reached no further code.
#include "harness.h"

#include <string.h>

#include "quic_config.h"
#include "webpki.h"
#include "webpki_ticket.h"

// The bytes behind each anchor's name and spki. Only their pointers and
// lengths are read here, so four bytes are enough.
#define ANCHOR_FIELD_MAX 4

static ch_tls t;
static ch_cfg cfg;
static uint8_t hostname[CH_HOSTNAME_MAX + 1];
static uint8_t names[CH_WEBPKI_ANCHOR_MAX][ANCHOR_FIELD_MAX];
static uint8_t spkis[CH_WEBPKI_ANCHOR_MAX][ANCHOR_FIELD_MAX];
static ch_trust_anchor anchors[CH_WEBPKI_ANCHOR_MAX];
static uint8_t pins[CH_SPKI_PIN_MAX][SHA256_LEN];
static uint8_t alpn_names[CH_ALPN_MAX][CH_ALPN_NAME_MAX];
static ch_alpn_protocol alpn[CH_ALPN_MAX];
static uint8_t params[CH_TRANSPORT_PARAMS_MAX];
static uint8_t rxbuf[4];
static uint8_t pin_slot[4];
static uint8_t psk[4];
static uint8_t binding[SHA256_LEN];

// Whether webpki_resumption_ok answered, and what.
static int resumption_called;
static int resumption_verdict;

int webpki_hostname_ok(const uint8_t *host, size_t host_len) {
    __CPROVER_assert(__CPROVER_r_ok(host, host_len), "hostname_ok: the name is readable");
    int ok = nondet_u8() & 1;
    __CPROVER_assume(!ok || (host_len >= 1 && host_len <= CH_HOSTNAME_MAX));
    return ok;
}

int webpki_resumption_ok(const ch_cfg *c) {
    __CPROVER_assert((c->spki_pins == NULL) == (c->spki_pin_count == 0) &&
                         c->spki_pin_count <= CH_SPKI_PIN_MAX,
                     "resumption_ok: the pin rule holds");
    __CPROVER_assert(c->spki_pin_count == 0 ||
                         __CPROVER_r_ok(c->spki_pins, c->spki_pin_count * SHA256_LEN),
                     "resumption_ok: the pins are readable");
    __CPROVER_assert(c->hostname_len <= CH_HOSTNAME_MAX &&
                         (c->hostname_len == 0 || __CPROVER_r_ok(c->hostname, c->hostname_len)),
                     "resumption_ok: the hostname rule holds");
    int counted = c->anchor_count <= CH_WEBPKI_ANCHOR_MAX &&
                  (c->anchor_count == 0 ||
                   __CPROVER_r_ok(c->anchors, c->anchor_count * sizeof c->anchors[0]));
    __CPROVER_assert(counted, "resumption_ok: the anchor count holds");
    __CPROVER_assume(counted);
    for (size_t i = 0; i < c->anchor_count; i++) {
        const ch_trust_anchor *a = &c->anchors[i];
        __CPROVER_assert(a->name != NULL && a->name_len > 0 && a->spki != NULL && a->spki_len > 0,
                         "resumption_ok: every anchor has a name and a key");
    }
    resumption_called = 1;
    resumption_verdict = nondet_u8() & 1;
    int unset = c->psk == NULL && c->psk_len == 0 && c->psk_id == NULL && c->psk_id_len == 0 &&
                c->resumption == 0 && c->ticket_binding == NULL;
    int ticket =
        c->resumption != 0 && c->psk != NULL && c->psk_id != NULL && c->ticket_binding != NULL;
    __CPROVER_assume(!resumption_verdict || unset || ticket);
    return resumption_verdict;
}

// ct_memeq's contract (ct.h): it reads n bytes of each operand and
// answers whether they are equal. The ct harness proves the body.
uint32_t ct_memeq(const uint8_t *a, const uint8_t *b, size_t n) {
    __CPROVER_assert(__CPROVER_r_ok(a, n) && __CPROVER_r_ok(b, n), "ct_memeq: operands readable");
    return nondet_u8() & 1;
}

static void level_ready(void *io, uint8_t level, uint8_t direction) {
    (void)io;
    (void)level;
    (void)direction;
}

static int epoch_load(void *io, uint32_t *value) {
    (void)io;
    (void)value;
    return 0;
}

static int epoch_store(void *io, uint32_t value) {
    (void)io;
    (void)value;
    return 0;
}

// A pointer that is NULL or p, chosen freshly.
static const uint8_t *maybe(const uint8_t *p) {
    return (nondet_u8() & 1) ? p : NULL;
}

// A length for a field whose pointer is set: at most cap bytes. With the
// pointer NULL, any length at all.
static size_t field_len(const uint8_t *p, size_t cap) {
    size_t n = nondet_size_t();
    __CPROVER_assume(p == NULL || n <= cap);
    return n;
}

static void havoc_anchors(void) {
    for (size_t i = 0; i < CH_WEBPKI_ANCHOR_MAX; i++) {
        const uint8_t *name = maybe(names[i]);
        const uint8_t *spki = maybe(spkis[i]);
        anchors[i] = (ch_trust_anchor){name, field_len(name, ANCHOR_FIELD_MAX), spki,
                                       field_len(spki, ANCHOR_FIELD_MAX)};
    }
    cfg.anchors = (nondet_u8() & 1) ? anchors : NULL;
    cfg.anchor_count = nondet_size_t();
}

static void havoc_alpn(void) {
    for (size_t i = 0; i < CH_ALPN_MAX; i++) {
        fill_nondet(alpn_names[i], CH_ALPN_NAME_MAX);
        const uint8_t *name = maybe(alpn_names[i]);
        alpn[i] = (ch_alpn_protocol){name, field_len(name, CH_ALPN_NAME_MAX)};
    }
    cfg.alpn_protocols = (nondet_u8() & 1) ? alpn : NULL;
    cfg.alpn_count = nondet_size_t();
}

static void havoc_trust(void) {
    cfg.hostname = maybe(hostname);
    cfg.hostname_len = field_len(cfg.hostname, sizeof hostname);
    cfg.now_seconds = (uint64_t)nondet_i64();
    havoc_anchors();
    cfg.spki_pins = maybe((const uint8_t *)pins);
    cfg.spki_pin_count = nondet_size_t();
    cfg.server_pubkey = maybe(pin_slot);
    cfg.server_pubkey_len = field_len(cfg.server_pubkey, sizeof pin_slot);
    cfg.server_pubkey2 = maybe(pin_slot);
    cfg.server_pubkey2_len = field_len(cfg.server_pubkey2, sizeof pin_slot);
    cfg.psk = maybe(psk);
    cfg.psk_len = field_len(cfg.psk, sizeof psk);
    cfg.psk_id = maybe(psk);
    cfg.psk_id_len = field_len(cfg.psk_id, sizeof psk);
    cfg.resumption = (int)nondet_u32();
    cfg.ticket_binding = maybe(binding);
    cfg.epoch_load = (nondet_u8() & 1) ? epoch_load : NULL;
    cfg.epoch_store = (nondet_u8() & 1) ? epoch_store : NULL;
    cfg.require_pq = (int)nondet_u32();
}

static void havoc_transport(void) {
    havoc_alpn();
    cfg.transport_params = maybe(params);
    cfg.transport_params_len = field_len(cfg.transport_params, sizeof params);
    cfg.on_level_ready = (nondet_u8() & 1) ? level_ready : NULL;
    cfg.buf = (nondet_u8() & 1) ? rxbuf : NULL;
    cfg.buf_len = nondet_size_t();
}

// The trust half of the contract, as webpki_cfg.h states it.
static int trust_holds(void) {
    int pins_ok = (cfg.spki_pins == NULL) == (cfg.spki_pin_count == 0) &&
                  cfg.spki_pin_count <= CH_SPKI_PIN_MAX;
    int hostname_set =
        cfg.hostname != NULL && cfg.hostname_len >= 1 && cfg.hostname_len <= CH_HOSTNAME_MAX;
    int pins_alone = cfg.spki_pin_count > 0 && cfg.anchors == NULL && cfg.anchor_count == 0 &&
                     ((cfg.hostname == NULL && cfg.hostname_len == 0) || hostname_set);
    int anchored = cfg.anchors != NULL && cfg.anchor_count >= 1 &&
                   cfg.anchor_count <= CH_WEBPKI_ANCHOR_MAX && hostname_set && cfg.now_seconds != 0;
    int slots_unset = cfg.server_pubkey == NULL && cfg.server_pubkey_len == 0 &&
                      cfg.server_pubkey2 == NULL && cfg.server_pubkey2_len == 0;
    return pins_ok && (pins_alone || anchored) && slots_unset && resumption_called &&
           resumption_verdict == 1;
}

// The transport half, as quic.h states it.
static int transport_holds(void) {
    return cfg.alpn_protocols != NULL && cfg.alpn_count >= 1 && cfg.alpn_count <= CH_ALPN_MAX &&
           cfg.transport_params != NULL && cfg.transport_params_len >= 1 &&
           cfg.transport_params_len <= CH_TRANSPORT_PARAMS_MAX && cfg.on_level_ready != NULL &&
           cfg.buf != NULL && cfg.buf_len >= CH_MIN_RXBUF && cfg.epoch_load == NULL &&
           cfg.epoch_store == NULL;
}

int main(void) {
    memset(&t, 0, sizeof t);
    memset(&cfg, 0, sizeof cfg);
    fill_nondet(hostname, sizeof hostname);
    havoc_trust();
    havoc_transport();
    t.cfg = cfg;
    int rc = quic_config_ok(&t, &cfg);
    __CPROVER_assert(rc == CH_OK || rc == CH_EINVAL, "the verdict is CH_OK or CH_EINVAL");
    if (rc == CH_OK) {
        __CPROVER_assert(trust_holds(), "CH_OK keeps the webpki trust rules");
        __CPROVER_assert(transport_holds(), "CH_OK keeps the QUIC transport rules");
    }
    return 0;
}
