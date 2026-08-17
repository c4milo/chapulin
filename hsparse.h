// Parsers for the two handshake messages that carry attacker-chosen
// bytes before the peer is authenticated: ServerHello (including
// HelloRetryRequest) and EncryptedExtensions. Pure functions over caller
// buffers — no I/O, no session state; handshake.c decides what the
// results mean. External linkage so proof, fuzz, and strictness-test
// builds reach the parsers without the state machine; the packaged
// library object localizes them like every other internal symbol.
#ifndef CH_HSPARSE_H
#define CH_HSPARSE_H

#include <stddef.h>
#include <stdint.h>

#include "x25519.h"

// Longest HelloRetryRequest cookie we echo; anything larger is a
// protocol error.
#define HSP_COOKIE_MAX 128

// The ServerHello.random value that marks a HelloRetryRequest
// (RFC 8446 §4.1.3).
extern const uint8_t hsp_hrr_magic[32];

// Everything hsp_parse_server_hello learns from one ServerHello.
typedef struct {
    int hrr;
    int version_ok;
    int have_share;
    int psk_ok;
    uint8_t seen; // extension types already parsed, bits per parse_server_hello_ext
    uint8_t server_pub[X25519_LEN];
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
// extension we never offered gets unsupported_extension, RFC 8446
// §4.2). Returns CH_OK or CH_EPROTO.
int hsp_parse_encrypted_exts(const uint8_t *body, size_t n, uint16_t *peer_limit, uint8_t *alert);

#endif
