// The two handshake messages a server may send after the handshake
// finishes, on a live authenticated session: NewSessionTicket and
// KeyUpdate (RFC 9846 §4.7). They ride handshake records, so ch_read
// meets them while the application is only asking for bytes.
//
// This is the last attacker-facing parser in the library. Everything it
// reads arrives decrypted from a peer that authenticated, which makes it
// less exposed than the handshake flight and no less parsed.
#ifndef CH_HANDSHAKE_POST_H
#define CH_HANDSHAKE_POST_H

#include <stddef.h>

#include "session.h"

// Reads whole post-handshake messages, starting from pt_len plaintext
// bytes already in cfg.buf and pulling further records when one message
// is fragmented across them. Returns CH_OK once the run is consumed, or
// an error; the caller turns the error into an alert.
int hspost_read(ch_tls *t, size_t pt_len);

#endif
