// session_report.h's calls: each converts the caller's storage once and reads one field
// (docs/decisions.md 185).
#include "session_report.h"

#include "session.h"
#include "session_convert.h"
#include "suite.h"
uint8_t ch_state(const ch_tls *t) {
    return tls_priv_const(t)->state;
}

uint16_t ch_group(const ch_tls *t) {
    return tls_priv_const(t)->group;
}

uint16_t ch_suite(const ch_tls *t) {
#ifdef CH_SUITE_AES_GCM
    return tls_priv_const(t)->suite;
#else
    (void)t;
    return CH_TLS_CHACHA20_POLY1305_SHA256;
#endif
}

uint8_t ch_psk_selected(const ch_tls *t) {
    return tls_priv_const(t)->psk_selected;
}

uint8_t ch_pin_slot(const ch_tls *t) {
    return tls_priv_const(t)->pin_slot;
}

uint32_t ch_epoch(const ch_tls *t) {
    return tls_priv_const(t)->epoch;
}

uint32_t ch_epoch_seen(const ch_tls *t) {
    return tls_priv_const(t)->epoch_seen;
}

uint8_t ch_epoch_status(const ch_tls *t) {
    return tls_priv_const(t)->epoch_status;
}

uint8_t ch_epoch_store_failed(const ch_tls *t) {
    return tls_priv_const(t)->epoch_store_failed;
}

#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_ROLE_SERVER)
uint8_t ch_alpn_selected(const ch_tls *t) {
    return tls_priv_const(t)->alpn_selected;
}

#endif
#ifdef CH_TRUST_WEBPKI
uint8_t ch_server_cert_type(const ch_tls *t) {
    return tls_priv_const(t)->server_cert_type;
}

#endif
#ifdef CH_ROLE_SERVER
size_t ch_sni_len(const ch_tls *t) {
    return tls_priv_const(t)->sni_len;
}

#endif
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
uint8_t ch_read_closed(const ch_tls *t) {
    return tls_priv_const(t)->read_closed;
}

uint16_t ch_peer_limit(const ch_tls *t) {
    return tls_priv_const(t)->peer_limit;
}

#endif
