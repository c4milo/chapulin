// matasapos public API: a TLS 1.3 client speaking exactly one profile —
// TLS_CHACHA20_POLY1305_SHA256, x25519, ECDHE-PSK (psk_dhe_ke). Zero heap:
// the session struct plus the caller's receive buffer is the entire
// working set. The caller supplies blocking I/O callbacks (bounded by its
// own timeouts) and a random source (rand.h).
#ifndef MS_TLS_H
#define MS_TLS_H

#include <stddef.h>
#include <stdint.h>

#include "record.h"
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

    // send moves all n bytes or returns -1; recv returns 1..n bytes or -1.
    // Both block, bounded by the caller's socket timeouts.
    int (*send)(void *io, const uint8_t *p, size_t n);
    int (*recv)(void *io, uint8_t *p, size_t n);
    void *io;

    // Optional; called once per NewSessionTicket.
    void (*on_ticket)(void *io, const ms_ticket *ticket);
} ms_cfg;

typedef struct {
    ms_cfg cfg;
    rec_dir rd;                    // server -> client protection
    rec_dir wr;                    // client -> server protection
    uint8_t rd_secret[SHA256_LEN]; // current traffic secrets, for KeyUpdate
    uint8_t wr_secret[SHA256_LEN];
    uint8_t res_master[SHA256_LEN];
    sha256 transcript;
    uint16_t peer_limit; // max plaintext per record the peer accepts
    uint8_t state;
    // Unread plaintext of the current record, inside cfg.buf.
    size_t pt_off;
    size_t pt_len;
    uint8_t tx[REC_HDR + MS_TX_PT + 1 + AEAD_TAG];
} ms_tls;

// Runs the full handshake. On MS_OK the session is ready for read/write.
// Any error wipes all key material and leaves the session dead.
int ms_connect(ms_tls *t, const ms_cfg *cfg);

// Sends n bytes as one or more records. Returns MS_OK or an error.
int ms_write(ms_tls *t, const uint8_t *p, size_t n);

// Receives into p, returning the byte count (>0), 0 on clean peer close
// (and on any read after), or an error. Handles NewSessionTicket and
// KeyUpdate internally.
int ms_read(ms_tls *t, uint8_t *p, size_t n);

// Sends close_notify (best effort) and wipes all key material.
void ms_close(ms_tls *t);

#endif
