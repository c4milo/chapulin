// chapulin's server API under TRANSPORT=quic: the TLS 1.3 server
// handshake of srv_flight.[ch], driven over QUIC's CRYPTO frames instead
// of TLS records. It sits beside srv.h the way quic.h sits beside tls.h,
// and it adds the calls a QUIC server needs that a TLS one does not.
//
// It is not a QUIC server. chapulin owns every key and every packet's
// protection; the caller owns UDP, packet numbers, loss recovery,
// congestion control, streams, connection IDs, CRYPTO frame reassembly
// and the decision to send a Retry. docs/quic_server.md states the split
// in full and what it costs.
//
// The packet calls are quic.h's and are not repeated here: ch_quic_seal,
// ch_quic_open, ch_quic_discard, ch_quic_key_update, ch_quic_close and
// the three readers serve either role, because they take key sets and
// bytes and read no side. What a server replaces is the driver, because
// a server waits where a client speaks.
//
// Output is a push, not a pull. A server has no ch_quic_crypto_out: one
// Certificate message is larger than ch_tls.tx, so there is nothing to
// stage and pull from, and the flight goes out through
// ch_srv_cfg.on_crypto_out as it is produced. srv_cfg.h states that
// contract and docs/quic_server.md item 4 the reasoning.
#ifndef CH_SRV_QUIC_H
#define CH_SRV_QUIC_H
#if defined(CH_ROLE_SERVER) && defined(CH_TRANSPORT_QUIC)

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "quic.h"

// The step numbers ch_quic.step holds in a server build. A server reads
// three messages and writes the rest, so the table is shorter than the
// client's: every send happens inside the step that read the message it
// answers, and no send has a step of its own.
#define SQ_STEP_AWAIT_CLIENT_HELLO 0
#define SQ_STEP_AWAIT_RETRY_HELLO 1
#define SQ_STEP_AWAIT_CLIENT_FINISHED 2
#define SQ_STEP_COMPLETE 3

// Prepares a server session. It reads the configuration, draws this
// connection's key share, and waits: unlike ch_quic_init it stages no
// message, because a server speaks second.
//
// Returns CH_EINVAL for every configuration ch_srv_accept refuses
// (srv.h), and additionally when cfg.srv.on_crypto_out is NULL, because a
// server whose flight reaches nobody completes no handshake. Nothing was
// sent and the session is dead.
//
// Requires: q and cfg are not NULL, and cfg outlives the session.
int ch_srv_quic_init(ch_quic *q, const ch_cfg *cfg);

// Delivers n CRYPTO bytes the peer sent at one encryption level. The
// server's own bytes leave through cfg.srv.on_crypto_out during this
// call, at the level each message belongs to, which is why one delivery
// can produce output at two levels: a ClientHello is answered by a
// ServerHello at CH_LEVEL_INITIAL and by the rest of the flight at
// CH_LEVEL_HANDSHAKE.
//
// Returns CH_OK when the bytes were taken, whether or not they completed
// a message. Every other code leaves the session dead, and ch_quic_alert
// names the alert the caller puts in a CONNECTION_CLOSE of type 0x0100
// plus that value (RFC 9001 section 4.8).
int ch_srv_quic_crypto_in(ch_quic *q, uint8_t level, const uint8_t *p, size_t n);

// Writes the Retry integrity tag of RFC 9001 section 5.8 over the Retry
// pseudo-packet the caller built, which is the server half of what
// ch_quic_retry_ok checks. The caller decides whether to send a Retry and
// owns every byte of the token; chapulin computes this tag and nothing
// else.
//
// Requires: n bytes readable at pseudo, GCM_TAG bytes writable at tag.
void ch_srv_quic_retry_tag(const uint8_t *pseudo, size_t n, uint8_t *tag);

#endif // CH_ROLE_SERVER && CH_TRANSPORT_QUIC
#endif
