// chapulin's non-blocking handshake API: the same TLS 1.3 client, over
// the same records, driven by a caller that owns the socket. Built with
// TRANSPORT=tcp-nonblocking.
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
// CH_OK from ch_record_state the session is connected and the caller moves
// to ch_read, ch_write and ch_close, whose callbacks no longer block: by
// then the caller holds the bytes and its send and recv are buffer copies.
// The record protection after the handshake is the same record.[ch] a
// TRANSPORT=tcp-blocking build uses, keyed the same way.
//
// After the handshake the caller's recv hands over whole records, and it
// returns 0 when it holds no record: ch_read then returns CH_RECORD_AGAIN
// (cfg.h) and the session stays connected. A record that carries no
// application data, a NewSessionTicket or a KeyUpdate, is handled before
// that answer, so a caller learns of it by its effect and calls ch_read
// again when the next record arrives. A post-handshake message split
// across records waits the same way, its first part kept in cfg.buf. A
// recv that returns 0 inside a record, after a record's first byte, breaks
// the whole-record promise and leaves the session dead with CH_EIO, as a
// short read does in TRANSPORT=tcp-blocking.
//
// Closing takes two calls, one per direction. The peer's close_notify
// closes the peer's direction alone (RFC 9846 §6.1): the ch_read that
// reads it returns 0, wipes the read key and does not call cfg.send, and
// every later ch_read returns 0 without calling cfg.recv. The write
// direction stays open, so ch_record_state still reports
// CH_ST_CONNECTED and ch_write still sends. The caller closes its own
// direction with ch_close, which sends this side's close_notify through
// cfg.send once and leaves the session CH_ST_CLOSED, whichever side
// closed first. ch_record_close after it is safe. ch_read calls cfg.send
// in two cases alone: to answer a KeyUpdate whose sender asked for one
// (RFC 9846 §4.7.3), and to send the alert of a failure.
//
// Result codes match quic.h's meanings. CH_OK means the call did what it
// says. CH_EINVAL from ch_record_init means it refused the configuration,
// staged nothing and left the session failed until the next init; from
// every other call, that the caller called out of order and nothing
// changed. CH_ECAP from ch_record_out means the caller's buffer was short,
// nothing was consumed, and the same call may run again with a larger
// one. CH_EPROTO from a call on a session that failed or closed, and from
// ch_read or ch_write before the handshake completes, changes nothing
// either (tls.h). Every other code leaves the session dead. A failure in
// ch_record_in or ch_srv_record_in, while the handshake runs, sends
// nothing, and ch_record_alert names the alert the caller should send
// before it closes. ch_read and ch_write send their failure's alert
// themselves, through cfg.send, and leave ch_record_alert at 0.
// ch_alert_sent names the alert in both cases (alert.h). A failure on the
// peer's fatal alert sends none and owes none, so both calls read 0 then
// (RFC 9846 §6.2).
#ifndef CH_TCP_NONBLOCKING_H
#define CH_TCP_NONBLOCKING_H
#ifdef CH_TRANSPORT_TCP_NONBLOCKING

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
typedef struct ch_record {
    ch_tls t;
    handshake_state hs;
    uint8_t step;  // TCP_NONBLOCKING_STEP_*, tcp_nonblocking_step.h
    uint8_t alert; // what ch_record_alert reports after a failure
    // Bytes of one finished record staged in t.tx and not yet collected,
    // and how many of them ch_record_out has already handed over. A partial
    // collection is what lets a caller with a small buffer make progress.
    size_t tx_len;
    size_t tx_off;
} ch_record;

// The client's driver, the three calls below, is declared only in an
// object with a client, which alone defines it (tcp_nonblocking.c). A
// ROLE=server object declares srv_tcp_nonblocking.h's in its place, so
// a server that calls one of these fails to compile rather than to link.
#if !defined(CH_ROLE_SERVER) || defined(CH_ROLE_BOTH)
// Prepares a session and stages its ClientHello. It reads the
// configuration and draws this connection's key share, and it sends
// nothing: the caller collects the hello with ch_record_out.
//
// Returns CH_EINVAL for every configuration ch_connect refuses (tls.h),
// cfg.send and cfg.recv among them. This mode calls neither while the
// handshake runs -- that is the whole point of it -- but ch_read and
// ch_write do once the session is connected, and a session that cannot
// carry application data is not worth completing. A caller whose I/O is
// an event loop fills them with buffer copies that never block, because
// by then it holds the bytes.
//
// A refusal stages nothing and leaves r failed, CH_ST_FAILED, until the
// next ch_record_init. One refusal differs from ch_connect's code: a CA
// build's ticket that the stored epoch retired, which ch_connect answers
// with CH_EAUTH, is CH_EINVAL here.
//
// Requires: r and cfg are not NULL, and cfg outlives the session.
int ch_record_init(ch_record *r, const ch_cfg *cfg);

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
// a record or a message. Returns CH_EINVAL, and consumes and changes
// nothing, while a record ch_record_out has not handed over yet is
// staged: the peer cannot have answered it. Returns CH_EPROTO without
// reading a byte on a session that failed or closed. Every other code
// leaves the session dead, and so does a record delivered here once
// ch_record_state reports CH_ST_CONNECTED: that record is ch_read's, and
// this call fails the session on it.
int ch_record_in(ch_record *r, uint8_t *p, size_t n, size_t *consumed);

// Collects bytes the caller must send. out_len is 0 when nothing is
// owed, which is the normal answer while waiting for the peer. A caller
// whose buffer is smaller than the staged record gets what fits and
// calls again; the record is finished when out_len is 0.
//
// Returns CH_ECAP only when cap is 0, because any other capacity makes
// progress. Returns CH_EINVAL on a session that failed or closed.
// Neither changes the session, and neither writes *out_len.
int ch_record_out(ch_record *r, uint8_t *out, size_t cap, size_t *out_len);
#endif

// CH_ST_START while the handshake runs, CH_ST_CONNECTED once it is done
// and the session is ready for ch_read and ch_write, CH_ST_FAILED after
// an error, and CH_ST_CLOSED after ch_close or ch_record_close
// (session.h). The peer's close_notify leaves it at CH_ST_CONNECTED,
// because ch_write still works; r->t.read_closed says it arrived.
uint8_t ch_record_state(const ch_record *r);

// The TLS alert a failure in ch_record_in or ch_srv_record_in chose, for
// the caller to send before it closes the connection. 0 when no such
// failure has happened, after a failure in ch_read or ch_write, which
// send their own alert, and after the peer's fatal alert, which this side
// answers with none (alert.h).
uint8_t ch_record_alert(const ch_record *r);

// Wipes every secret and marks the session dead. Safe on a session that
// already failed. It sends nothing, so a connected caller calls ch_close
// on &r->t first, which sends this side's close_notify.
void ch_record_close(ch_record *r);

// The length of the TLS record at the front of p, its 5-byte header
// included, or 0 while p holds less than that whole record. It reads the
// header's length field, p[3] and p[4], and no byte at or past p[n]. A
// caller whose recv hands ch_read whole records (above) asks it of the
// bytes it holds, passes that many to ch_read, and waits for more bytes
// when it answers 0. It reads no session, so either role asks it.
//
// A header whose length field is above 2^14 + 256 names a record no peer
// may send: RFC 9846 §5.2 caps the field there (rfc9846.txt:3595-3596). The
// answer for such a header is REC_HDR, the header alone, as soon as p holds
// it. ch_read reads those five bytes, refuses the length and fails the
// session, so the caller does not wait for a body the peer must not send.
// So every answer is 0 or a length from REC_HDR to n, and the largest is
// REC_HDR + 2^14 + 256, 16,645 bytes. A record of up to that length that
// cfg.buf_len cannot hold is ch_read's to refuse once it is whole; a peer
// that keeps to this endpoint's record_size_limit sends records of at most
// cfg.buf_len bytes.
size_t ch_record_whole_len(const uint8_t *p, size_t n);

#endif // CH_TRANSPORT_TCP_NONBLOCKING
#endif
