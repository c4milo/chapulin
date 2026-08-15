// The caller-facing configuration and result codes, at the bottom of the
// include graph so transport (io) and message building (hsmsg) can see
// them without reaching up into the session or the public API.
#ifndef MS_CFG_H
#define MS_CFG_H

#include <stddef.h>
#include <stdint.h>

#include "sha256.h"

#define MS_OK 0
#define MS_EIO (-1)     // transport failed or closed under us
#define MS_EPROTO (-2)  // peer broke the protocol; session dead
#define MS_EAUTH (-3)   // authentication failed; session dead
#define MS_ECAP (-4)    // caller buffer too small for the peer's message
#define MS_ECLOSED (-5) // clean close_notify from the peer

// Outgoing records are staged in the session struct so writes never
// disturb buffered incoming data; 512 bytes of plaintext per record.
#define MS_TX_PT 512

// Ticket identities beyond this cannot fit a future ClientHello, so
// larger tickets are silently dropped rather than surfaced.
#define MS_TICKET_ID_MAX 320

// A resumption ticket surfaced to the application: store psk + identity
// and present them on the next ms_connect (resumption = 1) for a cheaper
// reconnect. Valid only during the callback; copy what you keep.
typedef struct {
    const uint8_t *identity;
    size_t identity_len;
    uint8_t psk[SHA256_LEN];
    uint32_t lifetime_s;
    uint32_t age_add;
} ms_ticket;

typedef struct {
    // Provisioned PSK (external, resumption = 0) or a stored ticket PSK
    // (resumption = 1, obfuscated_age = ticket age ms + age_add).
    const uint8_t *psk;
    size_t psk_len;
    const uint8_t *psk_id;
    size_t psk_id_len;
    int resumption;
    uint32_t obfuscated_age;

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
    void (*on_ticket)(void *io, const ms_ticket *ticket);
} ms_cfg;

#endif
