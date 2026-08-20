// The caller-facing configuration and result codes, at the bottom of the
// include graph so transport (io) and message building (hsmsg) can see
// them without reaching up into the session or the public API.
#ifndef CH_CFG_H
#define CH_CFG_H

#include <stddef.h>
#include <stdint.h>

#include "sha256.h"

#define CH_OK 0
#define CH_EIO (-1)     // transport failed or closed under us
#define CH_EPROTO (-2)  // peer broke the protocol; session dead
#define CH_EAUTH (-3)   // authentication failed; session dead
#define CH_ECAP (-4)    // caller buffer too small for the peer's message
#define CH_ECLOSED (-5) // clean close_notify from the peer
#define CH_EINVAL (-6)  // invalid configuration or call; nothing was sent

// Outgoing records are staged in the session struct so writes never
// disturb buffered incoming data; 512 bytes of plaintext per record.
#define CH_TX_PT 512

// Smallest receive buffer ch_connect accepts. The profile's own
// control flights (ServerHello through Finished, tickets, KeyUpdate)
// reassemble within 512 bytes. Pinned mode also reassembles the
// server's Certificate message, and its size is the server's choice,
// so pinned deployments size the buffer for their server's chain (the
// e2e suite uses 2048). A feature that raises what a build itself
// requires (a certificate chain parser, a PQ key share) raises the
// floor here, so a buffer that build can never work with fails at
// configuration as CH_EINVAL instead of mid-handshake as CH_ECAP.
// The floor only rises: the base profile needs its 512 bytes in every
// build. The C++ wrapper re-includes this header; the C library build
// always runs the guard.
#ifndef CH_MIN_RXBUF
#define CH_MIN_RXBUF 512
#endif
#ifndef __cplusplus
_Static_assert(CH_MIN_RXBUF >= 512, "the receive floor never drops below the base profile's 512");
#endif

// Ticket identities beyond this cannot fit a future ClientHello, so
// larger tickets are silently dropped rather than surfaced.
#define CH_TICKET_ID_MAX 320

// A resumption ticket surfaced to the application: store psk + identity
// and present them on the next ch_connect (resumption = 1) for a cheaper
// reconnect. Valid only during the callback; copy what you keep.
typedef struct {
    const uint8_t *identity;
    size_t identity_len;
    uint8_t psk[SHA256_LEN];
    uint32_t lifetime_s;
    uint32_t age_add;
} ch_ticket;

typedef struct {
    // Authentication is one of two modes:
    //  - PSK: psk/psk_id set (external, resumption = 0) or a stored ticket
    //    (resumption = 1, obfuscated_age = ticket age ms + age_add).
    //  - Pinned key: psk NULL, server_pubkey = the server's raw public
    //    key, provisioned like a PSK would be. The key is an RSA modulus
    //    (256..384 bytes big-endian, exponent fixed at 65537, RSA-PSS) by
    //    default, or 64 P-256 bytes (X||Y, ECDSA) when built with
    //    -DCH_PIN_ECDSA — one algorithm per build, never both. An RSA
    //    modulus must be odd (any product of odd primes is); an even pin
    //    is provisioning corruption and fails ch_connect with CH_EINVAL. The server
    //    proves possession by signing the handshake; its certificate is
    //    never parsed, only hashed into the transcript, so there are no
    //    chains, no names, no expiry — one key, fail closed. Works against
    //    stock cert-based endpoints (Go, OpenSSL); tickets still arrive,
    //    so reconnects resume via PSK either way.
    const uint8_t *psk;
    size_t psk_len;
    const uint8_t *psk_id;
    size_t psk_id_len;
    int resumption;
    uint32_t obfuscated_age;
    const uint8_t *server_pubkey;
    size_t server_pubkey_len;

    // Optional second pin, the staged "next" key during server key
    // rotation: the handshake accepts a CertificateVerify matching either
    // slot and records which in ch_tls.pin_slot. Same length and oddness
    // rules as server_pubkey, never set without it. See docs/rotation.md.
    const uint8_t *server_pubkey2;
    size_t server_pubkey2_len;

    // Receive buffer; its size (minus record overhead) is advertised as
    // our record_size_limit, so the peer can never overflow it.
    uint8_t *buf;
    size_t buf_len;

    // send moves all n bytes and returns 0 — any other value, including a
    // positive byte count, is failure; recv returns 1..n bytes or -1.
    // Both block, bounded by the caller's socket timeouts.
    int (*send)(void *io, const uint8_t *p, size_t n);
    int (*recv)(void *io, uint8_t *p, size_t n);
    void *io;

    // Optional; called once per NewSessionTicket.
    void (*on_ticket)(void *io, const ch_ticket *ticket);
} ch_cfg;

#endif
