// What both tcp-nonblocking drivers do identically: take one inbound record,
// and die with the alert record the death owes.
//
// tcp_nonblocking.c drives the client and srv_tcp_nonblocking.c the
// server, and neither owns these. The framing is the same because a
// record reads the same from either side: the same header, the same
// compatibility-mode change_cipher_spec, the same key set in
// ch_tls.rd. INV-17 says every failure path wipes every secret the
// session holds, and that claim is checkable only if there is one list
// to check, so the list lives here rather than in two copies that
// drift.
#ifndef CH_TCP_NONBLOCKING_FRAME_H
#define CH_TCP_NONBLOCKING_FRAME_H
#ifdef CH_TRANSPORT_TCP_NONBLOCKING

#include <stddef.h>
#include <stdint.h>

#include "tcp_nonblocking.h"
#include "tls.h"

// Wipes every secret and clears the fields that say how much is staged
// or unread. session.h lists the same names beside the invariant they
// serve.
void tcp_nonblocking_wipe(ch_record *r);

// What tlsi_fail is on the blocking transport, minus the send. It writes
// the alert the failure chose into rec as one record, then wipes every
// secret and marks the session dead, so no key outlives the call. The
// record is sealed under the write key once this side has one
// (r->t.keys, the flag tlsi_send_alert reads), because RFC 9846 §6
// protects an alert under the current write key, and it goes in the
// clear before that. The caller holds no key, which is why the seal is
// the driver's.
//
// Returns the record's length: CH_ALERT_RECORD_LEN sealed, REC_HDR + 2 in
// the clear, and 0 when no alert is owed, which is the case after the
// peer's fatal alert (RFC 9846 §6.2). The caller emits the record the way
// its driver emits every other one: the client stages it for
// ch_record_out, and the server pushes it through cfg.srv.on_record_out.
size_t tcp_nonblocking_fail(ch_record *r, uint8_t rec[CH_ALERT_RECORD_LEN]);

// Whether the session has stopped, by either door.
int tcp_nonblocking_session_dead(const ch_record *r);

// Takes one record's plaintext into the handshake buffer. A record that
// arrives before the handshake keys is already plaintext; one after them
// is unprotected in place, which rec_open supports through pt == rec.
//
// Requires: REC_HDR + body_len bytes readable and writable at rec, and
// outer is that record's own type byte.
int tcp_nonblocking_take_record(ch_record *r, uint8_t *rec, size_t body_len, uint8_t outer);

#endif // CH_TRANSPORT_TCP_NONBLOCKING
#endif
