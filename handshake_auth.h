// Server authentication: the Certificate and CertificateVerify flight,
// and the CA build's monotonic revocation rule. Split out of
// handshake.c, which owns the state machine that calls this; the two
// entry points below are the only ones it needs. The rest stays
// private here. A CH_TRANSPORT_QUIC build declares a third, because its
// driver reads one handshake message per call and the flight is two
// messages.
#ifndef CH_HANDSHAKE_AUTH_H
#define CH_HANDSHAKE_AUTH_H

#include "handshake_record.h"

// Reads the server's Certificate and CertificateVerify and authenticates
// the peer: against the pinned key in a raw-pin build, or against a
// chain up to the pinned CA key in a CA-mode build. Returns CH_OK, or
// an error with h->alert set.
//
// Under CH_TRANSPORT_QUIC it stops one message earlier. It reads the
// Certificate, verifies the chain the trust mode asks for, adds the raw
// message to the transcript and returns CH_OK there, with h->leaf
// written under a CA mode and TRUST=webpki, h->t->pin_slot written under
// a CA mode and h->t->epoch_status written under a CA mode. It has not
// read the CertificateVerify, and the peer is not authenticated yet:
// hsa_read_certificate_verify does that in the next step. The split
// exists because the QUIC driver returns to its caller between
// handshake messages, so one call may read one message
// (docs/quic.md, "Entry points and their contracts").
int hsa_server_auth(handshake_state *h);

#if defined(CH_TRANSPORT_QUIC) || defined(CH_TRANSPORT_RECORD)
// Reads the server's CertificateVerify and verifies its signature over
// the handshake transcript, which authenticates the peer (RFC 9846
// §4.5.2). It takes the transcript hash as it stands, rebuilds §4.5.2's
// signed content from it, and verifies: against h->leaf.key under
// a CA mode and TRUST=webpki, the leaf key hsa_server_auth copied out,
// and against cfg.server_pubkey and then cfg.server_pubkey2 under
// a raw mode. On success it adds the raw message to the transcript.
//
// Requires an hsa_server_auth that returned CH_OK in the same session,
// and no write to h->t->transcript between the two calls: this call
// recomputes the hash rather than carrying it, so anything hashed in
// between would change the content it verifies. Requires a whole
// message to be readable, which the driver checks with
// hsr_peek_message before it runs the step.
//
// Returns CH_OK, with the peer authenticated and h->t->pin_slot set to
// 1 or 2 under a raw mode, naming the pin that verified the signature.
//
// Returns CH_EAUTH with ALERT_DECRYPT_ERROR when no key verified the
// signature, which RFC 9846 §4.5.2 requires (rfc9846.txt:3106-3107).
// Returns CH_EAUTH with ALERT_ILLEGAL_PARAMETER under TRUST=webpki when
// the message names a signature scheme the leaf's own key cannot
// produce. Returns CH_EPROTO with ALERT_UNEXPECTED_MESSAGE for any
// other handshake type, and CH_EPROTO with ALERT_DECODE_ERROR for a
// body that is not the one offered algorithm and then the signature,
// exact-fill. It also returns what hsr_next_msg returns, which under
// this transport is CH_EPROTO with ALERT_DECODE_ERROR for a header
// naming a body above 0x4000 bytes, or CH_EINVAL when no whole message
// is unread.
//
// On every error the transcript holds what hsa_server_auth added and
// nothing more, and the caller turns the error into quic_fail.
int hsa_read_certificate_verify(handshake_state *h);
#endif

// Raises the stored revocation epoch to the leaf's, once the peer has
// proved it holds the leaf key. A no-op unless the caller configured
// the epoch callbacks. Runs after the server Finished, never before:
// the epoch outlives the session, so an unauthenticated certificate
// must not move it (docs/ca.md, INV-21).
void hsa_epoch_commit(handshake_state *h);

#endif
