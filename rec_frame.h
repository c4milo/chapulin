// What both tcp-nonblocking drivers do identically: take one inbound record,
// and die.
//
// rec.c drives the client and srv_rec.c the server, and neither owns
// these. The framing is the same because a record reads the same from
// either side: the same header, the same compatibility-mode
// change_cipher_spec, the same key set in ch_tls.rd. INV-17 says every
// failure path wipes every secret the session holds, and that claim is
// checkable only if there is one list to check, so the list lives here
// rather than in two copies that drift.
#ifndef CH_REC_FRAME_H
#define CH_REC_FRAME_H
#ifdef CH_TRANSPORT_TCP_NONBLOCKING

#include <stddef.h>
#include <stdint.h>

#include "rec.h"

// Wipes every secret and clears the fields that say how much is staged
// or unread. session.h lists the same names beside the invariant they
// serve.
void rec_wipe(ch_record *r);

// What tlsi_fail is on the blocking transport, minus the alert record:
// this mode sends nothing itself, so the alert goes to r->alert and the
// caller sends it. Every secret is wiped and the session is dead.
// Returns rc, so a caller can tail-call it.
int rec_fail(ch_record *r, int rc);

// Whether the session has stopped, by either door.
int rec_session_dead(const ch_record *r);

// Takes one record's plaintext into the handshake buffer. A record that
// arrives before the handshake keys is already plaintext; one after them
// is unprotected in place, which rec_open supports through pt == rec.
//
// Requires: REC_HDR + body_len bytes readable and writable at rec, and
// outer is that record's own type byte.
int rec_take_record(ch_record *r, uint8_t *rec, size_t body_len, uint8_t outer);

#endif // CH_TRANSPORT_TCP_NONBLOCKING
#endif
