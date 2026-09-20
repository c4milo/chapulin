// How a server's handshake message leaves the server. srv_flight.c writes
// the messages; this pair decides what happens to the bytes, which is the
// one thing the two transports do differently.
//
// Over TLS records a message in the clear is staged at t->tx + REC_HDR and
// written as one plaintext record, a protected one is sealed into as many
// records as the peer's record_size_limit allows, and the Certificate is
// streamed because no frame holds a whole chain.
//
// Over QUIC there are no records at all (RFC 9001 section 4.1.3,
// rfc9001.txt:462-464). Every call hands its bytes to
// ch_srv_cfg.on_crypto_out at handshake_state.level, and a message split
// across calls is what a CRYPTO frame's byte stream already expects.
// docs/quic_server.md item 4 states why a server pushes where the client
// stages.
#ifndef CH_SRV_OUT_H
#define CH_SRV_OUT_H
#ifdef CH_ROLE_SERVER

#include <stddef.h>
#include <stdint.h>

#include "handshake_record.h"
#include "record.h"
#include "session.h"

// The largest plaintext one call carries. Over TLS it is this build's cap
// lowered to the client's record_size_limit; over QUIC no record bounds it
// and the cap alone applies.
size_t srv_out_limit(const ch_tls *t);

// Where a message sent in the clear is staged inside ch_tls.tx. A TLS
// build leaves room for the record header it writes in front; a QUIC build
// writes no header, and session.h gives that build a tx with no room for
// one, so the origin is the buffer itself.
#ifdef CH_TRANSPORT_QUIC
#define SRV_OUT_STAGE 0
#else
#define SRV_OUT_STAGE REC_HDR
#endif

// Sends the n bytes staged at t->tx + REC_HDR in the clear. Over TLS that
// is one plaintext handshake record; over QUIC it is n CRYPTO bytes and
// the record header is never written.
int srv_out_plain(handshake_state *h, size_t n);

// Sends n bytes of one handshake message under the current protection.
// Over TLS that is one or more sealed records; over QUIC it is the bytes
// themselves. pt lies outside t->tx, where rec_seal writes.
int srv_out_sealed(handshake_state *h, const uint8_t *pt, size_t n);

// A message written in pieces, hashed and sent a fragment at a time: the
// Certificate is the one message no frame holds, because the chain stays
// in the caller's flash. rc is sticky the way wbuf's err is, so the caller
// reads one code.
typedef struct {
    handshake_state *h;
    size_t len;
    int rc;
    uint8_t buf[CH_TX_PT];
} srv_frag;

// Hashes what the writer holds and sends it.
void srv_frag_flush(srv_frag *f);

// Adds n bytes, flushing whenever the writer fills.
void srv_frag_bytes(srv_frag *f, const uint8_t *p, size_t n);

#endif // CH_ROLE_SERVER
#endif
