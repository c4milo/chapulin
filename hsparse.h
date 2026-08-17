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

// Everything hsp_parse_sh learns from one ServerHello.
typedef struct {
    int hrr;
    int ver_ok;
    int have_share;
    int psk_ok;
    uint8_t seen; // extension types already parsed, bits per parse_sh_ext
    uint8_t server_pub[X25519_LEN];
    const uint8_t *cookie; // into the caller's message; NULL if absent
    size_t cookielen;
} sh_info;

// Parses a ServerHello body (handshake header stripped) into si, which
// the caller zeroes first. psk_mode says whether the ClientHello offered
// a PSK. Returns CH_OK or CH_EPROTO; on CH_OK check si->hrr before
// trusting the share.
int hsp_parse_sh(const uint8_t *body, size_t n, sh_info *si, int psk_mode);

// Parses an EncryptedExtensions body. Lowers *peer_limit to the peer's
// record_size_limit when one arrives; writes *alert only for an
// extension we never offered. Returns CH_OK or CH_EPROTO.
int hsp_parse_ee(const uint8_t *body, size_t n, uint16_t *peer_limit, uint8_t *alert);

#endif
