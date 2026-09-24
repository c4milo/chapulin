// chapulin's server API under TRANSPORT=record: the TLS 1.3 server
// handshake of srv_flight.[ch], driven by a caller that owns the socket.
// It sits beside srv.h the way rec.h sits beside tls.h, and it adds the
// calls a record-mode server needs that a blocking one does not.
//
// srv.h's ch_srv_accept runs the handshake by calling cfg.send and
// cfg.recv, which block. That is the right shape for the firmware
// chapulin targets, where a blocking socket is all there is, and the
// wrong shape for a host whose I/O is an event loop: a callback that
// blocks cannot sit under a completion queue without a thread to park.
// This header gives that host the shape srv_quic.h already gives a QUIC
// server.
//
// The post-handshake calls are rec.h's and are not repeated here.
// ch_record_state, ch_record_alert and ch_record_close read no side, and
// ch_read, ch_write and ch_close are the same record-layer calls a
// client uses, because record.[ch] names no side either.
//
// Output is a push, not a pull. A server has no ch_srv_record_out: one
// Certificate message is larger than ch_tls.tx, so there is nothing to
// stage and pull from, and the flight goes out through
// ch_srv_cfg.on_record_out as it is produced. srv_cfg.h states that
// contract and docs/server.md the reasoning.
#ifndef CH_SRV_REC_H
#define CH_SRV_REC_H
#if defined(CH_ROLE_SERVER) && defined(CH_TRANSPORT_RECORD)

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "rec.h"

// The step numbers ch_record.step holds in a server build. A server reads
// three messages and writes the rest, so the table is shorter than the
// client's: every send happens inside the step that read the message it
// answers, and no send has a step of its own.
//
// They mirror srv_quic.h's SQ_STEP_ constructor for constructor, because
// the handshake is the same handshake and only the transport under it
// differs. Consecutive from 0, with SR_STEP_COMPLETE largest.
#define SR_STEP_AWAIT_CLIENT_HELLO 0
#define SR_STEP_AWAIT_RETRY_HELLO 1
#define SR_STEP_AWAIT_CLIENT_FINISHED 2
#define SR_STEP_COMPLETE 3

// Prepares a server session. It reads the configuration and waits:
// unlike ch_record_init it stages no message, because a server speaks
// second.
//
// Returns CH_EINVAL for every configuration ch_srv_accept refuses
// (srv.h), and additionally when cfg.srv.on_record_out is NULL, because
// a server whose flight reaches nobody completes no handshake. Nothing
// was sent and the session is dead.
//
// Requires: r and cfg are not NULL, and cfg outlives the session.
int ch_srv_record_init(ch_record *r, const ch_cfg *cfg);

// Delivers n bytes the caller read from its socket and reports how many
// it consumed. It takes whole records only and runs the handshake as far
// as they carry it; a trailing partial record is left for the caller to
// re-present with more bytes after it. That is why chapulin holds no
// receive buffer of its own in this mode.
//
// p is not const: a protected record is unprotected in place, so the
// bytes up to *consumed are rewritten. The bytes after it are untouched,
// and the caller must present them again unchanged.
//
// The server's own records leave through cfg.srv.on_record_out during
// this call, which is why one delivery of a ClientHello produces the
// whole server flight.
//
// The call stops after the record that completes the handshake, with
// *consumed covering it and nothing past it: a client may send its first
// application record in the same segment as its Finished, and those
// bytes belong to ch_read once ch_record_state reports CH_ST_CONNECTED.
//
// Returns CH_OK when the bytes were taken, whether or not they completed
// a record or a message. Every other code leaves the session dead, and
// ch_record_alert names the alert the caller sends before it closes.
int ch_srv_record_in(ch_record *r, uint8_t *p, size_t n, size_t *consumed);

#endif // CH_ROLE_SERVER && CH_TRANSPORT_RECORD
#endif
