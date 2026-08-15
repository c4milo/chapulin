// matasapos public API: a TLS 1.3 client speaking exactly one profile —
// TLS_CHACHA20_POLY1305_SHA256, x25519, ECDHE-PSK (psk_dhe_ke). Zero heap:
// the session struct plus the caller's receive buffer is the entire
// working set. The caller supplies blocking I/O callbacks (bounded by its
// own timeouts) and a random source (rand.h). Configuration and result
// codes live in cfg.h; the session struct in session.h.
#ifndef MS_TLS_H
#define MS_TLS_H

#include "session.h"

// Runs the full handshake. On MS_OK the session is ready for read/write.
// Any error wipes all key material and leaves the session dead.
int ms_connect(ms_tls *t, const ms_cfg *cfg);

// Sends n bytes as one or more records. Returns MS_OK or an error.
int ms_write(ms_tls *t, const uint8_t *p, size_t n);

// Receives into p (n >= 1), returning the byte count (>0), 0 on clean
// peer close (and on any read after), or an error. Handles
// NewSessionTicket and KeyUpdate internally.
int ms_read(ms_tls *t, uint8_t *p, size_t n);

// Sends close_notify (only under live keys) and wipes all key material.
void ms_close(ms_tls *t);

#endif
