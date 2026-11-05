// The public calls of TRANSPORT=quic-nonblocking that take a ch_quic or a ch_tls
// (docs/decisions.md 185). Each converts the caller's storage once, and then reads one field or
// calls the body that quic_session.h declares. quic.h, srv_quic.h and alert.h state each contract.
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING

#include "quic_session.h"

#include "alert.h"
#include "quic.h"
#include "session_convert.h"
#include "srv_quic.h"

#if !defined(CH_ROLE_SERVER) || defined(CH_ROLE_BOTH)
int ch_quic_init(ch_quic *q, const ch_cfg *cfg) {
    return quic_init(quic_priv(q), cfg);
}

int ch_quic_crypto_in(ch_quic *q, uint8_t level, const uint8_t *p, size_t n) {
    return quic_crypto_in(quic_priv(q), level, p, n);
}

int ch_quic_crypto_out(ch_quic *q, uint8_t level, uint8_t *out, size_t cap, size_t *out_len) {
    return quic_crypto_out(quic_priv(q), level, out, cap, out_len);
}

int ch_quic_switch_version(ch_quic *q, uint32_t version) {
    return quic_switch_version(quic_priv(q), version);
}
#endif

#ifdef CH_ROLE_SERVER
int ch_srv_quic_init(ch_quic *q, const ch_cfg *cfg) {
    return srv_quic_init(quic_priv(q), cfg);
}

int ch_srv_quic_crypto_in(ch_quic *q, uint8_t level, const uint8_t *p, size_t n) {
    return srv_quic_crypto_in(quic_priv(q), level, p, n);
}
#endif

int ch_quic_initial_keys(ch_quic *q, const uint8_t *dcid, size_t dcid_len) {
    return quic_initial_keys(quic_priv(q), dcid, dcid_len);
}

int ch_quic_seal(ch_quic *q, uint8_t level, uint32_t version, uint64_t pn, size_t pn_len,
                 const uint8_t *hdr, size_t hdr_len, const uint8_t *pt, size_t pt_len, uint8_t *out,
                 size_t cap, size_t *out_len) {
    return quic_seal(quic_priv(q), level, version, pn, pn_len, hdr, hdr_len, pt, pt_len, out, cap,
                     out_len);
}

int ch_quic_seal_close(ch_quic *q, uint8_t level, uint32_t version, uint64_t pn, size_t pn_len,
                       const uint8_t *hdr, size_t hdr_len, const uint8_t *pt, size_t pt_len,
                       uint8_t *out, size_t cap, size_t *out_len) {
    return quic_seal_close(quic_priv(q), level, version, pn, pn_len, hdr, hdr_len, pt, pt_len, out,
                           cap, out_len);
}

int ch_quic_open(ch_quic *q, uint8_t level, uint32_t version, uint8_t *pkt, size_t pkt_len,
                 size_t pn_off, uint64_t largest_pn, uint64_t current_phase_lowest_pn,
                 uint8_t *key_set, uint64_t *pn, size_t *pt_len) {
    return quic_open(quic_priv(q), level, version, pkt, pkt_len, pn_off, largest_pn,
                     current_phase_lowest_pn, key_set, pn, pt_len);
}

uint8_t ch_quic_retry_ok(const ch_quic *q, uint32_t version, const uint8_t *pseudo, size_t n,
                         const uint8_t tag[CH_QUIC_RETRY_TAG_LEN]) {
    return quic_session_retry_ok(quic_priv_const(q), version, pseudo, n, tag);
}

int ch_quic_key_update(ch_quic *q) {
    return quic_key_update(quic_priv(q));
}

void ch_quic_drop_previous_keys(ch_quic *q) {
    quic_drop_previous_keys(quic_priv(q));
}

int ch_quic_discard(ch_quic *q, uint8_t level) {
    return quic_discard(quic_priv(q), level);
}

uint64_t ch_quic_error_code(const ch_quic *q) {
    return quic_error_code(quic_priv_const(q));
}

void ch_quic_close(ch_quic *q) {
    quic_close(quic_priv(q));
}

uint32_t ch_quic_negotiated_version(const ch_quic *q) {
    return quic_priv_const(q)->t.quic_negotiated_version;
}

uint8_t ch_quic_key_phase(const ch_quic *q) {
    return quic_priv_const(q)->key_phase;
}

uint8_t ch_quic_state(const ch_quic *q) {
    return quic_priv_const(q)->t.state;
}

ch_tls *ch_quic_tls(ch_quic *q) {
    return tls_public(&quic_priv(q)->t);
}

uint8_t ch_quic_levels_ready(const ch_quic *q) {
    return quic_priv_const(q)->levels_ready;
}

uint8_t ch_quic_alert(const ch_quic *q) {
    return quic_priv_const(q)->alert;
}

// alert.h states both contracts. quic_fail writes alert_sent beside q->alert, so the first answers
// what ch_quic_alert answers, for a caller that reads one call across its TCP and QUIC sessions.
// QUIC carries no alert record, so no peer alert is read here and ch_tls declares no
// alert_received.
uint8_t ch_alert_sent(const ch_tls *t) {
    return tls_priv_const(t)->alert_sent;
}

uint8_t ch_alert_received(const ch_tls *t) {
    (void)t;
    return 0;
}

#endif // CH_TRANSPORT_QUIC_NONBLOCKING
