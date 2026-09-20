// chapulin's non-blocking handshake API: the same TLS 1.3 client, over
// the same records, driven by a caller that owns the socket. Built with
// TRANSPORT=record.
//
// tls.h's ch_connect runs the handshake by calling cfg.send and cfg.recv,
// which block. That is the right shape for the firmware chapulin targets,
// where a blocking socket is all there is, and the wrong shape for a host
// whose I/O is an event loop: a callback that blocks cannot sit under a
// completion queue without a thread to park. This header gives that host
// the shape quic.h already gives QUIC — bytes in, bytes out, no callback
// on the handshake path.
//
// What it covers and what it does not. It drives the handshake alone. On
// CH_OK from ch_rec_state the session is connected and the caller moves
// to ch_read, ch_write and ch_close, whose callbacks no longer block: by
// then the caller holds the bytes and its send and recv are buffer copies.
// The record protection after the handshake is the same record.[ch] a
// TRANSPORT=tls build uses, keyed the same way.
//
// Result codes match quic.h's meanings. CH_OK means the call did what it
// says. CH_EINVAL means the caller called out of order and nothing
// changed. CH_ECAP from ch_rec_out means the caller's buffer was short,
// nothing was consumed, and the same call may run again with a larger
// one. Every other code leaves the session dead, and ch_rec_alert names
// the alert the caller should send before it closes.
#ifndef CH_REC_H
#define CH_REC_H
#ifdef CH_TRANSPORT_RECORD

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "handshake_record.h"
#include "session.h"

// One handshake in progress. It holds everything that survives a return,
// because the driver returns to its caller between messages: the ch_tls a
// blocking build keeps alone, the handshake_state that build holds on
// ch_handshake's stack frame, and the driver's own three fields.
//
// It is not copyable: hs.t points at t, and every entry rewrites that
// pointer to its own &r->t, so a copy cannot leave a dangling pointer
// inside a step.
typedef struct ch_rec {
    ch_tls t;
    handshake_state hs;
    uint8_t step;  // HSR_STEP_*, rec_step.h
    uint8_t alert; // what ch_rec_alert reports after a failure
    // Bytes of one finished record staged in t.tx and not yet collected,
    // and how many of them ch_rec_out has already handed over. A partial
    // collection is what lets a caller with a small buffer make progress.
    size_t tx_len;
    size_t tx_off;
} ch_rec;

// Prepares a session and stages its ClientHello. It reads the
// configuration and draws this connection's key share, and it sends
// nothing: the caller collects the hello with ch_rec_out.
//
// Returns CH_EINVAL for every configuration ch_connect refuses (tls.h),
// cfg.send and cfg.recv among them. This mode calls neither while the
// handshake runs -- that is the whole point of it -- but ch_read and
// ch_write do once the session is connected, and a session that cannot
// carry application data is not worth completing. A caller whose I/O is
// an event loop fills them with buffer copies that never block, because
// by then it holds the bytes.
//
// Requires: r and cfg are not NULL, and cfg outlives the session.
int ch_rec_init(ch_rec *r, const ch_cfg *cfg);

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
// Returns CH_OK when the bytes were taken, whether or not they completed
// a record or a message. Every other code leaves the session dead.
int ch_rec_in(ch_rec *r, uint8_t *p, size_t n, size_t *consumed);

// Collects bytes the caller must send. out_len is 0 when nothing is
// owed, which is the normal answer while waiting for the peer. A caller
// whose buffer is smaller than the staged record gets what fits and
// calls again; the record is finished when out_len is 0.
//
// Returns CH_ECAP only when cap is 0, because any other capacity makes
// progress.
int ch_rec_out(ch_rec *r, uint8_t *out, size_t cap, size_t *out_len);

// CH_ST_START while the handshake runs, CH_ST_CONNECTED once it is done
// and the session is ready for ch_read and ch_write, CH_ST_FAILED after
// an error (session.h).
uint8_t ch_rec_state(const ch_rec *r);

// The TLS alert a failure chose, for the caller to send before it closes
// the connection. 0 when no failure has happened.
uint8_t ch_rec_alert(const ch_rec *r);

// Wipes every secret and marks the session dead. Safe on a session that
// already failed.
void ch_rec_close(ch_rec *r);

#endif // CH_TRANSPORT_RECORD
#endif
