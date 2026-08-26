// Server authentication: the Certificate and CertificateVerify flight,
// and the CA build's monotonic revocation rule. Split out of
// handshake.c, which owns the state machine that calls this; the two
// entry points below are the only ones it needs. The rest stays
// private here.
#ifndef CH_HANDSHAKE_AUTH_H
#define CH_HANDSHAKE_AUTH_H

#include "handshake_record.h"

// Reads the server's Certificate and CertificateVerify and authenticates
// the peer: against the pinned key in a raw-pin build, or against a
// chain up to the pinned CA key in a TRUST=ca build. Returns CH_OK, or
// an error with h->alert set.
int hsa_server_auth(handshake_state *h);

// Raises the stored revocation epoch to the leaf's, once the peer has
// proved it holds the leaf key. A no-op unless the caller configured
// the epoch callbacks. Runs after the server Finished, never before:
// the epoch outlives the session, so an unauthenticated certificate
// must not move it (docs/ca.md, INV-21).
void hsa_epoch_commit(handshake_state *h);

#endif
