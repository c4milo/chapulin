// The one way a QUIC session dies, shared by both drivers.
//
// INV-17 says every failure path wipes every secret the session holds.
// That claim is checkable only if there is one list to check, so the list
// lives here and quic.c and srv_quic.c both call it rather than each
// keeping a copy that drifts from the other.
#ifndef CH_QUIC_FAIL_H
#define CH_QUIC_FAIL_H
#ifdef CH_TRANSPORT_QUIC

#include <stdint.h>

#include "quic.h"

// Wipes every secret and clears the two fields that say which keys are
// usable and how many bytes are unread. session.h lists the same names
// beside the invariant they serve.
void quic_wipe(ch_quic *q);

// What tlsi_fail is on the TLS transport, minus the alert record, which
// QUIC has no way to carry: the alert goes to q->alert for ch_quic_alert
// to report, every secret is wiped and the session is dead. It leaves
// q->error_code alone, so a caller that wrote a code before it called
// still reports that code. Returns rc, so a caller can tail-call it.
int quic_fail(ch_quic *q, int rc);

// The RFC 9001 section 4.1.3 refusals that kill the session, in one place
// because both write PROTOCOL_VIOLATION (rfc9001.txt:482-486,
// rfc9001.txt:491-493).
int quic_fail_level(ch_quic *q);

#endif // CH_TRANSPORT_QUIC
#endif
