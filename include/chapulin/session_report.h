// What a session reports to its caller: one read call for each field of ch_tls_priv that a caller
// reads. tls.h, tcp_nonblocking.h and quic.h include this header. A tcp-nonblocking session
// passes ch_tcp_tls(r) and a QUIC session ch_quic_tls(q), as alert.h's two calls take them.
//
// A caller reads a session through these calls and alert.h's. Its ch_tls is storage whose bytes
// are the library's (session_storage.h): the keys, the secrets, the transcript and the state the
// handshake writes. The caller allocates it, because chapulin allocates nothing.
//
// Each call reads its field and nothing else, in session_report.c. Each takes a session that an
// init call started, or one that ch_tls's zero bytes fill.
#ifndef CH_SESSION_REPORT_H
#define CH_SESSION_REPORT_H

#include <stddef.h>
#include <stdint.h>

#include "result.h"
#include "session_storage.h"

// Every object exports these calls, so their symbol names carry the object's transport, as
// alert.h's do: an image that links a tcp-nonblocking object and a QUIC object holds one of
// each (docs/decisions.md 61 and 185).
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#define ch_state ch_state_quic_nonblocking
#define ch_group ch_group_quic_nonblocking
#define ch_suite ch_suite_quic_nonblocking
#define ch_psk_selected ch_psk_selected_quic_nonblocking
#define ch_pin_slot ch_pin_slot_quic_nonblocking
#define ch_epoch ch_epoch_quic_nonblocking
#define ch_epoch_seen ch_epoch_seen_quic_nonblocking
#define ch_epoch_status ch_epoch_status_quic_nonblocking
#define ch_epoch_store_failed ch_epoch_store_failed_quic_nonblocking
#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_ROLE_SERVER)
#define ch_alpn_selected ch_alpn_selected_quic_nonblocking
#endif
#ifdef CH_TRUST_WEBPKI
#define ch_server_cert_type ch_server_cert_type_quic_nonblocking
#endif
#ifdef CH_ROLE_SERVER
#define ch_sni_len ch_sni_len_quic_nonblocking
#endif
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
#define ch_read_closed ch_read_closed_quic_nonblocking
#define ch_peer_limit ch_peer_limit_quic_nonblocking
#endif
#elif defined(CH_TRANSPORT_TCP_NONBLOCKING)
#define ch_state ch_state_tcp_nonblocking
#define ch_group ch_group_tcp_nonblocking
#define ch_suite ch_suite_tcp_nonblocking
#define ch_psk_selected ch_psk_selected_tcp_nonblocking
#define ch_pin_slot ch_pin_slot_tcp_nonblocking
#define ch_epoch ch_epoch_tcp_nonblocking
#define ch_epoch_seen ch_epoch_seen_tcp_nonblocking
#define ch_epoch_status ch_epoch_status_tcp_nonblocking
#define ch_epoch_store_failed ch_epoch_store_failed_tcp_nonblocking
#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_ROLE_SERVER)
#define ch_alpn_selected ch_alpn_selected_tcp_nonblocking
#endif
#ifdef CH_TRUST_WEBPKI
#define ch_server_cert_type ch_server_cert_type_tcp_nonblocking
#endif
#ifdef CH_ROLE_SERVER
#define ch_sni_len ch_sni_len_tcp_nonblocking
#endif
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
#define ch_read_closed ch_read_closed_tcp_nonblocking
#define ch_peer_limit ch_peer_limit_tcp_nonblocking
#endif
#else
#define ch_state ch_state_tcp_blocking
#define ch_group ch_group_tcp_blocking
#define ch_suite ch_suite_tcp_blocking
#define ch_psk_selected ch_psk_selected_tcp_blocking
#define ch_pin_slot ch_pin_slot_tcp_blocking
#define ch_epoch ch_epoch_tcp_blocking
#define ch_epoch_seen ch_epoch_seen_tcp_blocking
#define ch_epoch_status ch_epoch_status_tcp_blocking
#define ch_epoch_store_failed ch_epoch_store_failed_tcp_blocking
#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_ROLE_SERVER)
#define ch_alpn_selected ch_alpn_selected_tcp_blocking
#endif
#ifdef CH_TRUST_WEBPKI
#define ch_server_cert_type ch_server_cert_type_tcp_blocking
#endif
#ifdef CH_ROLE_SERVER
#define ch_sni_len ch_sni_len_tcp_blocking
#endif
#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
#define ch_read_closed ch_read_closed_tcp_blocking
#define ch_peer_limit ch_peer_limit_tcp_blocking
#endif
#endif

// CH_ST_START, CH_ST_CONNECTED, CH_ST_CLOSED or CH_ST_FAILED (session.h).
uint8_t ch_state(const ch_tls *t);

// The NamedGroup the key exchange ran, a CH_GROUP_ value (cfg.h), and 0 before the handshake
// accepts a ServerHello's key_share.
uint16_t ch_group(const ch_tls *t);

// The cipher suite the session runs, a CH_TLS_ value (public_sizes.h). A build with the AES-GCM
// suites answers 0 until a ServerHello or a HelloRetryRequest names one. A build that holds
// ChaCha20 alone runs it in every session, so it answers CH_TLS_CHACHA20_POLY1305_SHA256.
uint16_t ch_suite(const ch_tls *t);

// 1 when a PSK authenticated the handshake, so the session resumed, and 0 for a full handshake
// and before a ServerHello is accepted.
uint8_t ch_psk_selected(const ch_tls *t);

// Which pin authenticated the server: 1 for cfg.server_pubkey, 2 for cfg.server_pubkey2, and 0
// before a pinned handshake completes and in every build without pins (docs/rotation.md).
uint8_t ch_pin_slot(const ch_tls *t);

// The revocation epoch of a CA build (docs/ca.md): the stored epoch, the epoch the peer's
// certificate carried, how the rule judged it (CH_EPOCH_ in cfg.h), and 1 when the store of a
// raised epoch failed and the caller owes a retry. Each answers 0 outside a CA build.
uint32_t ch_epoch(const ch_tls *t);
uint32_t ch_epoch_seen(const ch_tls *t);
uint8_t ch_epoch_status(const ch_tls *t);
uint8_t ch_epoch_store_failed(const ch_tls *t);

#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_ROLE_SERVER)
// The index in cfg.alpn_protocols of the protocol ALPN selected, or CH_ALPN_NONE (cfg.h) when
// none was selected. A build without ALPN declares no such call.
uint8_t ch_alpn_selected(const ch_tls *t);
#endif

#ifdef CH_TRUST_WEBPKI
// The certificate type the server's EncryptedExtensions selected, CH_CERT_TYPE_X509 or
// CH_CERT_TYPE_RAW_PUBLIC_KEY (webpki_cfg.h), and CH_CERT_TYPE_X509 when it sent none.
uint8_t ch_server_cert_type(const ch_tls *t);
#endif

#ifdef CH_ROLE_SERVER
// How many bytes of the client's server_name the handshake copied into cfg.srv.sni_buf, and 0
// when the client sent none or the name did not fit sni_cap (srv_cfg.h).
size_t ch_sni_len(const ch_tls *t);
#endif

#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
// 1 once ch_read has returned 0 for the peer's close_notify: the peer's direction is closed,
// and this side may still write (tls.h).
uint8_t ch_read_closed(const ch_tls *t);

// The most plaintext one record carries toward the peer: the peer's record_size_limit, less
// the inner content type, and 0 before the handshake reads it. ch_writable_len reads it.
uint16_t ch_peer_limit(const ch_tls *t);
#endif

#endif
