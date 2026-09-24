#include "webpki_ticket.h"

#include "buf.h"
#include "ch_assert.h"
#include "ct.h"
#include "hkdf.h"
#include "webpki.h"

// The label the binding's HMAC covers ahead of the hash, so a binding
// can never equal an HMAC this tree computes for another purpose under
// the same key.
static const uint8_t binding_label[] = {'c', 'h', 'a', 'p', 'u', 'l', 'i', 'n', ' ', 'w', 'e',
                                        'b', 'p', 'k', 'i', ' ', 't', 'i', 'c', 'k', 'e', 't'};

// Hashes n as 8 big-endian bytes, so no two field sequences hash the
// same byte string.
static void hash_len(sha256 *s, size_t n) {
    uint64_t v = (uint64_t)n;
    uint8_t be[8];
    wbuf w;
    wb_init(&w, be, sizeof be);
    wb_u16(&w, (uint16_t)(v >> 48));
    wb_u16(&w, (uint16_t)(v >> 32));
    wb_u16(&w, (uint16_t)(v >> 16));
    wb_u16(&w, (uint16_t)v);
    sha256_update(s, be, sizeof be);
}

static uint8_t ascii_lower(uint8_t c) {
    return c >= 'A' && c <= 'Z' ? (uint8_t)(c + ('a' - 'A')) : c;
}

void webpki_ticket_config_hash(const ch_cfg *cfg, uint8_t out[SHA256_LEN]) {
    // The hostname rule admits 1 to CH_HOSTNAME_MAX bytes before any
    // caller runs this (webpki_ticket.h).
    CH_ASSERT(cfg->hostname_len <= CH_HOSTNAME_MAX);
    uint8_t lower[CH_HOSTNAME_MAX] = {0};
    for (size_t i = 0; i < cfg->hostname_len; i++) {
        lower[i] = ascii_lower(cfg->hostname[i]);
    }
    sha256 s;
    sha256_init(&s);
    hash_len(&s, cfg->hostname_len);
    sha256_update(&s, lower, cfg->hostname_len);
    hash_len(&s, cfg->anchor_count);
    for (size_t i = 0; i < cfg->anchor_count; i++) {
        const ch_trust_anchor *a = &cfg->anchors[i];
        hash_len(&s, a->name_len);
        sha256_update(&s, a->name, a->name_len);
        hash_len(&s, a->spki_len);
        sha256_update(&s, a->spki, a->spki_len);
    }
    sha256_final(&s, out);
}

void webpki_ticket_binding(const uint8_t psk[SHA256_LEN], const uint8_t config_hash[SHA256_LEN],
                           uint8_t out[SHA256_LEN]) {
    uint8_t msg[sizeof binding_label + SHA256_LEN];
    wbuf w;
    wb_init(&w, msg, sizeof msg);
    wb_bytes(&w, binding_label, sizeof binding_label);
    wb_bytes(&w, config_hash, SHA256_LEN);
    hmac_sha256(psk, SHA256_LEN, msg, w.len, out);
}

// Every PSK field unset: the full handshake, which checks the chain.
static int psk_unset(const ch_cfg *cfg) {
    return cfg->psk == NULL && cfg->psk_len == 0 && cfg->psk_id == NULL && cfg->psk_id_len == 0 &&
           cfg->resumption == 0 && cfg->ticket_binding == NULL;
}

// The shape of a presented ticket, before its binding is checked: the
// PSK length ks_res_psk writes and an identity handshake_post.c would
// have passed to on_ticket.
static int ticket_shape_ok(const ch_cfg *cfg) {
    return cfg->resumption != 0 && cfg->psk != NULL && cfg->psk_len == SHA256_LEN &&
           cfg->psk_id != NULL && cfg->psk_id_len > 0 && cfg->psk_id_len <= CH_TICKET_ID_MAX &&
           cfg->ticket_binding != NULL;
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
    webpki_ticket_config_hash(cfg, config_hash);
    webpki_ticket_binding(cfg->psk, config_hash, expected);
    uint32_t same = ct_memeq(expected, cfg->ticket_binding, SHA256_LEN);
    ct_wipe(expected, sizeof expected);
    return same != 0;
}
