// Parsers for the two handshake messages that carry attacker-chosen
// bytes before the peer is authenticated: ServerHello (including
// HelloRetryRequest) and EncryptedExtensions. Pure functions over caller
// buffers — no I/O, no session state; handshake.c decides what the
// results mean. External linkage so proof, fuzz, and strictness-test
// builds reach the parsers without the state machine; the packaged
// library object localizes them like every other internal symbol.
#ifndef CH_HANDSHAKE_PARSER_H
#define CH_HANDSHAKE_PARSER_H

#include <stddef.h>
#include <stdint.h>

#include "x25519.h"

// Longest HelloRetryRequest cookie we echo; anything larger is a
// protocol error.
#define HSP_COOKIE_MAX 128

// The ServerHello.random value that marks a HelloRetryRequest
// (RFC 9846 §4.2.3).
extern const uint8_t hsp_hrr_magic[32];

// Everything hsp_parse_server_hello learns from one ServerHello.
typedef struct {
    int hrr;
    int version_ok;
    int have_share;
    int psk_ok;
    uint8_t seen; // extension types already parsed, bits per parse_server_hello_ext
    uint8_t server_pub[X25519_LEN];
#ifdef CH_KEX_PQ
    // The ML-KEM ciphertext, MLKEM_CT_LEN bytes into the caller's
    // message — like cookie, the pointer dies at the next record read;
    // the handshake decapsulates before one runs.
    const uint8_t *server_ct;
#endif
    const uint8_t *cookie; // into the caller's message; NULL if absent
    size_t cookie_len;
} server_hello_info;

// Parses a ServerHello body (handshake header stripped) into info, which
// the caller zeroes first. psk_mode says whether the ClientHello offered
// a PSK. Returns CH_OK or CH_EPROTO; on CH_OK check info->hrr before
// trusting the share.
int hsp_parse_server_hello(const uint8_t *body, size_t n, server_hello_info *info, int psk_mode);

// Parses an EncryptedExtensions body. Lowers *peer_limit to the peer's
// record_size_limit when one arrives. Callers seed *alert with their
// default; the parser overwrites it only when it knows better (an
// extension we never offered gets unsupported_extension, RFC 9846
// §4.3). Returns CH_OK or CH_EPROTO.
// Certificate body framing: the empty certificate_request_context,
// then the exact-fill CertificateEntry list. On CH_OK *list points
// into body — the raw bytes the CA build's certificate parser
// consumes. The caller seeds *alert; the parser overwrites it when
// it knows better (a nonempty context).
int hsp_parse_certificate(const uint8_t *body, size_t n, const uint8_t **list, size_t *list_len,
                          uint8_t *alert);

// CertificateVerify body: the one offered algorithm, then the
// signature, exact-fill. On CH_OK *sig points into body and lives as
// long as it does. The caller seeds *alert; the parser overwrites it
// only when it knows better (wrong algorithm).
int hsp_parse_certificate_verify(const uint8_t *body, size_t n, const uint8_t **sig,
                                 size_t *sig_len, uint8_t *alert);

int hsp_parse_encrypted_exts(const uint8_t *body, size_t n, uint16_t *peer_limit, uint8_t *alert);

#endif
