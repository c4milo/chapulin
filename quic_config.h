// The configuration rules ch_quic_init applies, and the stored
// revocation epoch it loads. They sit apart from quic.[ch] because
// quic.c holds the driver and the packet calls and CLAUDE.md caps a
// hand-written file at 500 lines; this is the one concern that splits
// off cleanly, because no other call in the mode reads a rule here.
//
// The rules are tls.c's, which a TRANSPORT=quic object does not
// compile, plus the three RFC 9001 adds. quic.c states each one beside
// the call, and quic.h states them for the caller.
#ifndef CH_QUIC_CONFIG_H
#define CH_QUIC_CONFIG_H
#ifdef CH_TRANSPORT_QUIC

#include "cfg.h"
#include "session.h"

// Judges cfg and, under TRUST=ca, loads the stored revocation epoch
// into t. ch_quic_init calls it once, before it draws a secret or
// builds a message, so a refusal leaves nothing to wipe.
//
// Requires: t is the zeroed session whose cfg copy is already written;
// cfg is not NULL and outlives the session.
//
// Returns CH_OK when every rule holds. Returns CH_EINVAL for any
// refusal, and CH_EAUTH when a resuming ticket's epoch sits below the
// stored one, which is the code tls.c's ch_connect returns there.
// ch_quic_init turns every one of them into CH_EINVAL, because quic.h
// gives that call one refusal code.
//
// It writes t->epoch, t->epoch_seen and t->epoch_status under TRUST=ca
// and nothing outside t in any build.
int quic_config_ok(ch_tls *t, const ch_cfg *cfg);

#endif // CH_TRANSPORT_QUIC
#endif
