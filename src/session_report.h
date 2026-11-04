// What a session reports to its caller: one read call for each field of ch_tls that a caller
// reads. tls.h, tcp_nonblocking.h and quic.h include this header. A tcp-nonblocking session
// passes &r->t and a QUIC session &q->t, as alert.h's two calls take them.
//
// A caller reads ch_tls through these calls and alert.h's, and through no field. Every other
// field of ch_tls is the library's: the keys, the secrets, the transcript and the state the
// handshake writes. A caller that reads one depends on a layout no release keeps, and a caller
// that writes one breaks the session. ch_tls stays a public struct for one reason: the caller
// allocates it, because chapulin allocates nothing.
//
// Each call is static inline, so no object exports it, and each reads its field and nothing
// else. Each takes a session that an init call started, or one that ch_tls's zero bytes fill.
#ifndef CH_SESSION_REPORT_H
#define CH_SESSION_REPORT_H

#include <stddef.h>
#include <stdint.h>

#include "session.h"

// CH_ST_START, CH_ST_CONNECTED, CH_ST_CLOSED or CH_ST_FAILED (session.h).
static inline uint8_t ch_state(const ch_tls *t) {
    return t->state;
}

// The NamedGroup the key exchange ran, a CH_GROUP_ value (cfg.h), and 0 before the handshake
// accepts a ServerHello's key_share.
static inline uint16_t ch_group(const ch_tls *t) {
    return t->group;
}

// The cipher suite the session runs, a CH_TLS_ value (suite.h). A build that holds the AES-GCM
// suites answers 0 until a ServerHello or a HelloRetryRequest names one. A build that holds
// ChaCha20 alone runs it in every session, so it answers CH_TLS_CHACHA20_POLY1305_SHA256.
static inline uint16_t ch_suite(const ch_tls *t) {
#ifdef CH_SUITE_AES_GCM
    return t->suite;
#else
    (void)t;
    return CH_TLS_CHACHA20_POLY1305_SHA256;
#endif
}

// 1 when a PSK authenticated the handshake, so the session resumed, and 0 for a full handshake
// and before a ServerHello is accepted.
static inline uint8_t ch_psk_selected(const ch_tls *t) {
    return t->psk_selected;
}

// Which pin authenticated the server: 1 for cfg.server_pubkey, 2 for cfg.server_pubkey2, and 0
// before a pinned handshake completes and in every build without pins (docs/rotation.md).
static inline uint8_t ch_pin_slot(const ch_tls *t) {
    return t->pin_slot;
}

// The revocation epoch of a CA build (docs/ca.md): the stored epoch, the epoch the peer's
// certificate carried, how the rule judged it (CH_EPOCH_ in cfg.h), and 1 when the store of a
// raised epoch failed and the caller owes a retry. Each answers 0 outside a CA build.
static inline uint32_t ch_epoch(const ch_tls *t) {
    return t->epoch;
}
static inline uint32_t ch_epoch_seen(const ch_tls *t) {
    return t->epoch_seen;
}
static inline uint8_t ch_epoch_status(const ch_tls *t) {
    return t->epoch_status;
}
static inline uint8_t ch_epoch_store_failed(const ch_tls *t) {
    return t->epoch_store_failed;
}

#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_ROLE_SERVER)
// The index in cfg.alpn_protocols of the protocol ALPN selected, or CH_ALPN_NONE (cfg.h) when
// none was selected. A build without ALPN declares no such call.
static inline uint8_t ch_alpn_selected(const ch_tls *t) {
    return t->alpn_selected;
}
#endif

#ifdef CH_TRUST_WEBPKI
// The certificate type the server's EncryptedExtensions selected, CH_CERT_TYPE_X509 or
// CH_CERT_TYPE_RAW_PUBLIC_KEY (webpki_cfg.h), and CH_CERT_TYPE_X509 when it sent none.
static inline uint8_t ch_server_cert_type(const ch_tls *t) {
    return t->server_cert_type;
}
#endif

#ifdef CH_ROLE_SERVER
// How many bytes of the client's server_name the handshake copied into cfg.srv.sni_buf, and 0
// when the client sent none or the name did not fit sni_cap (srv_cfg.h).
static inline size_t ch_sni_len(const ch_tls *t) {
    return t->sni_len;
}
#endif

#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
// 1 once ch_read has returned 0 for the peer's close_notify: the peer's direction is closed,
// and this side may still write (tls.h).
static inline uint8_t ch_read_closed(const ch_tls *t) {
    return t->read_closed;
}

// The most plaintext one record carries toward the peer: the peer's record_size_limit, less
// the inner content type, and 0 before the handshake reads it. ch_writable_len reads it.
static inline uint16_t ch_peer_limit(const ch_tls *t) {
    return t->peer_limit;
}
#endif

#endif
