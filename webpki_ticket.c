#include "webpki_ticket.h"

#include "buf.h"
#include "ch_assert.h"
#include "cpu.h"
#include "ct.h"
#include "hkdf.h"
#include "suite.h"
#include "webpki.h"

// The label the binding's HMAC covers ahead of the hash, so a binding
// can never equal an HMAC this tree computes for another purpose under
// the same key.
static const uint8_t binding_label[] = {'c', 'h', 'a', 'p', 'u', 'l', 'i', 'n', ' ', 'w', 'e',
                                        'b', 'p', 'k', 'i', ' ', 't', 'i', 'c', 'k', 'e', 't'};

// sha256_update and sha256_final on the path cpu names: sha256.h's
// entries in a host object, and sha256.c's calls in a device object,
// which holds one SHA-256 and reads no value (webpki_ticket.h).
static void config_update(uint32_t cpu, sha256 *s, const uint8_t *in, size_t n) {
#ifdef CH_CPU_RUNTIME
    sha256_update_cpu(cpu, s, in, n);
#else
    (void)cpu;
    sha256_update(s, in, n);
#endif
}

static void config_final(uint32_t cpu, sha256 *s, uint8_t out[SHA256_LEN]) {
#ifdef CH_CPU_RUNTIME
    sha256_final_cpu(cpu, s, out);
#else
    (void)cpu;
    sha256_final(s, out);
#endif
}

// Hashes n as 8 big-endian bytes, so no two field sequences hash the
// same byte string.
static void hash_len(uint32_t cpu, sha256 *s, size_t n) {
    uint64_t v = (uint64_t)n;
    uint8_t be[8];
    wbuf w;
    wb_init(&w, be, sizeof be);
    wb_u16(&w, (uint16_t)(v >> 48));
    wb_u16(&w, (uint16_t)(v >> 32));
    wb_u16(&w, (uint16_t)(v >> 16));
    wb_u16(&w, (uint16_t)v);
    config_update(cpu, s, be, sizeof be);
}

static uint8_t ascii_lower(uint8_t c) {
    return c >= 'A' && c <= 'Z' ? (uint8_t)(c + ('a' - 'A')) : c;
}

void webpki_ticket_config_hash(uint32_t cpu, const ch_cfg *cfg, uint8_t out[SHA256_LEN]) {
    // The hostname rule admits 1 to CH_HOSTNAME_MAX bytes before any
    // caller runs this (webpki_ticket.h).
    CH_ASSERT(cfg->hostname_len <= CH_HOSTNAME_MAX);
    uint8_t lower[CH_HOSTNAME_MAX] = {0};
    for (size_t i = 0; i < cfg->hostname_len; i++) {
        lower[i] = ascii_lower(cfg->hostname[i]);
    }
    sha256 s;
    sha256_init(&s);
    hash_len(cpu, &s, cfg->hostname_len);
    config_update(cpu, &s, lower, cfg->hostname_len);
    hash_len(cpu, &s, cfg->anchor_count);
    for (size_t i = 0; i < cfg->anchor_count; i++) {
        const ch_trust_anchor *a = &cfg->anchors[i];
        hash_len(cpu, &s, a->name_len);
        config_update(cpu, &s, a->name, a->name_len);
        hash_len(cpu, &s, a->spki_len);
        config_update(cpu, &s, a->spki, a->spki_len);
    }
    hash_len(cpu, &s, cfg->spki_pin_count);
    const uint8_t *pin = cfg->spki_pins;
    for (size_t i = 0; i < cfg->spki_pin_count; i++) {
        config_update(cpu, &s, pin, SHA256_LEN);
        pin += SHA256_LEN;
    }
    config_final(cpu, &s, out);
}

int webpki_takes_tickets(const ch_cfg *cfg) {
    return cfg->on_ticket != NULL;
}

void webpki_ticket_binding(uint32_t cpu, const uint8_t *psk, size_t psk_len,
                           const uint8_t config_hash[SHA256_LEN], uint8_t out[SHA256_LEN]) {
    uint8_t msg[sizeof binding_label + SHA256_LEN];
    wbuf w;
    wb_init(&w, msg, sizeof msg);
    wb_bytes(&w, binding_label, sizeof binding_label);
    wb_bytes(&w, config_hash, SHA256_LEN);
#ifdef CH_CPU_RUNTIME
    hmac_sha256_cpu(cpu, psk, psk_len, msg, w.len, out);
#else
    (void)cpu;
    hmac_sha256(psk, psk_len, msg, w.len, out);
#endif
}

// Every PSK field unset and no ticket: the full handshake, which checks
// the chain.
static int psk_unset(const ch_cfg *cfg) {
    return cfg->psk == NULL && cfg->psk_len == 0 && cfg->psk_id == NULL && cfg->psk_id_len == 0 &&
           cfg->ticket == NULL;
}

// A PSK length ks_res_psk writes: the hash length of a suite this client
// can run (ch_ticket.psk_len).
static int psk_len_ok(size_t psk_len) {
#ifdef CH_CLIENT_AES_SUITES
    if (psk_len == SHA384_LEN) {
        return 1;
    }
#endif
    return psk_len == SHA256_LEN;
}

// The shape of a presented ticket, before its binding is checked: a
// PSK length ks_res_psk writes and an identity handshake_post.c would
// have passed to on_ticket. hspost_present_ticket wrote the ticket's PSK
// and identity into these fields of the session's copy, so a PSK without
// a ticket is an external one, which this mode refuses.
static int ticket_shape_ok(const ch_cfg *cfg) {
    return cfg->ticket != NULL && cfg->psk != NULL && psk_len_ok(cfg->psk_len) &&
           cfg->psk_id != NULL && cfg->psk_id_len > 0 && cfg->psk_id_len <= CH_TICKET_ID_MAX;
}

int webpki_resumption_ok(const ch_cfg *cfg) {
    if (psk_unset(cfg)) {
        return 1;
    }
    if (!ticket_shape_ok(cfg)) {
        return 0;
    }
    uint8_t config_hash[SHA256_LEN];
    uint8_t expected[SHA256_LEN];
    webpki_ticket_config_hash(CH_CFG_CPU(*cfg), cfg, config_hash);
    webpki_ticket_binding(CH_CFG_CPU(*cfg), cfg->psk, cfg->psk_len, config_hash, expected);
    uint32_t same = ct_memeq(expected, cfg->ticket->ticket.binding, SHA256_LEN);
    ct_wipe(expected, sizeof expected);
    return same != 0;
}
