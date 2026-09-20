// The TLS 1.3 server handshake: one entry point that drives the
// caller's I/O from the first ClientHello to connected, including at
// most one HelloRetryRequest round. It is the mirror of
// handshake.[ch]. Only a ROLE=server build compiles it.
// docs/server.md states the role.
//
// The order is the call order. This file calls srv_flight.h's handlers
// in one straight line, so there is no state variable to desynchronize
// and no message can run out of turn, which is INV-22's mechanism
// sentence holding for the server as it holds for the client. The line
// is split into three functions rather than one for a measured reason:
// each `if (rc != CH_OK) return rc;` counts one against
// .clang-tidy's cognitive-complexity threshold of 15, and the flight
// has more than fifteen of them, so a single driver cannot land. The
// client splits the same way and for the same reason.
//
// Everything it learns lands in the ch_tls session; every failure
// sends the alert the failing handler chose, wipes all key material
// and leaves the session dead.
#ifndef CH_SRV_HANDSHAKE_H
#define CH_SRV_HANDSHAKE_H
#ifdef CH_ROLE_SERVER

#include "session.h"

// Runs the whole server handshake over the session's I/O callbacks.
// It zeroes a handshake_state on its own frame, runs the flight, takes
// h->alert on the way out, wipes the state with ct_wipe and fails the
// session on any error, which is how ch_handshake wraps the client's
// (handshake.c:133-156).
//
// Requires a session whose cfg ch_srv_accept has already checked, and
// a connection the caller has already accepted. It opens no socket:
// accepting is the caller's, as connecting is for a client.
//
// Returns CH_OK with the session connected and ready for ch_read and
// ch_write, or the code the failing handler returned. It never leaves
// the session half-live: every non-CH_OK path wipes.
int srv_handshake(ch_tls *t);

#endif // CH_ROLE_SERVER
#endif
