// chapulin's server API under TRANSPORT=quic-nonblocking: the TLS 1.3 server
// handshake of srv_flight.[ch], driven over QUIC's CRYPTO frames instead
// of TLS records. It sits beside srv.h the way quic.h sits beside tls.h,
// and it adds the calls a QUIC server needs that a TCP one does not.
//
// It is not a QUIC server. chapulin owns every key and every packet's
// protection; the caller owns UDP, packet numbers, loss recovery,
// congestion control, streams, connection IDs, CRYPTO frame reassembly
// and the decision to send a Retry. docs/quic_server.md states the split
// in full and what it costs.
//
// The packet calls are quic.h's and are not repeated here: ch_quic_seal,
// ch_quic_seal_close, ch_quic_open, ch_quic_discard, ch_quic_key_update,
// ch_quic_close, ch_quic_negotiated_version and the three readers serve
// either role, because they take key sets, versions and bytes and read no
// side. ch_quic_switch_version does not: RFC 9369 section 4.1 gives the
// switch to a client, and quic.h declares it beside the client's driver.
// What a server replaces is the driver, because a server waits where a
// client speaks.
//
// The Retry token is not repeated here either: ch_srv_quic_token_mint and
// ch_srv_quic_token_check are quic_token.h's, which this header includes.
// They take the token key and no session, because a Retry precedes every
// piece of connection state.
//
// Output is a push, not a pull. A server has no ch_quic_crypto_out: one
// Certificate message is larger than ch_tls.tx, so there is nothing to
// stage and pull from, and the flight goes out through
// ch_srv_cfg.on_crypto_out as it is produced. srv_cfg.h states that
// contract and docs/quic_server.md item 4 the reasoning.
#ifndef CH_SRV_QUIC_H
#define CH_SRV_QUIC_H
#if defined(CH_ROLE_SERVER) && defined(CH_TRANSPORT_QUIC_NONBLOCKING)

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "quic.h"
#include "quic_token.h"

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
// server whose flight reaches nobody completes no handshake, and when
// cfg.quic_original_version, the Version field of the client's first
// Initial packet, is one this build derives no keys for (quic_version.h),
// 0 included. Nothing was sent and the session is dead. On CH_OK the
// negotiated version is the original one (ch_quic_negotiated_version).
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
// The first ClientHello's delivery hands the client's transport
// parameters to cfg.on_transport_params and then asks
// cfg.srv.choose_version for the negotiated version, once per connection
// and before any byte goes out (srv_cfg.h, RFC 9369 section 4.1). The
// caller seals every later CRYPTO frame in that version, the
// HelloRetryRequest and the ServerHello included, and reads it with
// ch_quic_negotiated_version. A second ClientHello after a
// HelloRetryRequest repeats the first's parameters, which the frozen
// digest holds it to, and neither callback fires for it.
//
// Returns CH_OK when the bytes were taken, whether or not they completed
// a message. Returns CH_EINVAL, and consumes and changes nothing, when
// level is above CH_LEVEL_APPLICATION, or when it is above the level the
// server reads while no byte sits unconsumed at that one: RFC 9001
// section 4.1.3 leaves such bytes for QUIC to hold until their keys
// arrive, as ch_quic_crypto_in says for a client (quic.h). The flight
// returns no CH_EINVAL: ch_srv_quic_init refused every configuration it
// could fail on (srv_identities_usable, srv_auth.h). Returns CH_EPROTO
// without reading a byte on a session that failed or closed.
//
// Every other code leaves the session dead, and ch_quic_error_code names
// the code the caller puts in CONNECTION_CLOSE: 0x0100 plus ch_quic_alert
// for a TLS alert (RFC 9001 section 4.8). CH_EIO is the caller's own
// failure: an on_crypto_out that refused bytes, or a choose_version
// answer this build derives no keys for, which fails with internal_error
// before any byte goes out. The server fails through
// quic_fail as a client does, so it keeps the write keys of each level it
// had installed, and ch_quic_seal_close seals that close once at each
// (docs/quic_server.md, "When the handshake fails").
int ch_srv_quic_crypto_in(ch_quic *q, uint8_t level, const uint8_t *p, size_t n);

// Writes the Retry integrity tag of RFC 9001 section 5.8 over the Retry
// pseudo-packet the caller built, which is the server half of what
// ch_quic_retry_ok checks. The caller decides whether to send a Retry and
// builds the pseudo-packet; the token inside it is the one
// ch_srv_quic_token_mint wrote, or one of the caller's own. version is the
// Version field of the Retry, which a server sends in the original version
// (RFC 9369 section 4.1, rfc9369.txt:221-222), and it chooses the key and
// the nonce. The call takes no session, so it cannot check that version is
// the original one: the caller passes cfg.quic_original_version.
//
// Requires: n bytes readable at pseudo, GCM_TAG bytes writable at tag.
//
// Returns CH_OK and writes GCM_TAG bytes. Returns CH_EINVAL and writes
// nothing when this build derives no keys for version (quic_version.h).
int ch_srv_quic_retry_tag(uint32_t version, const uint8_t *pseudo, size_t n, uint8_t *tag);

#endif // CH_ROLE_SERVER && CH_TRANSPORT_QUIC_NONBLOCKING
#endif
