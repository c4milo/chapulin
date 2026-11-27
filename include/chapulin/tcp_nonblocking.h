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
// CH_OK from ch_tcp_state the session is connected and the caller moves
// to ch_read_in_place, ch_seal_in_place and ch_close_out. The record
// protection after the handshake is the same record.[ch] a
// TRANSPORT=tcp-blocking build uses, keyed the same way.
//
// cfg.buf serves the handshake alone (docs/decisions.md 247). The
// session reassembles handshake messages in it while the handshake runs.
// When the session connects, fails or closes, it wipes all cfg.buf_len
// bytes and forgets the pointer, and from then on it neither reads nor
// writes the buffer. So one buffer can serve many connections one after
// another, the way a server keeps a pool of buffers for the handshakes in
// flight. Two rules go with that, and the caller keeps both:
//   - One handshake uses one buffer at a time. Between calls a session
//     may keep the first part of a handshake message in cfg.buf, so two
//     handshakes in flight need two buffers. A pool holds one buffer for
//     each handshake in flight, and a handshake gives its buffer back when
//     ch_tcp_state answers CH_ST_CONNECTED, CH_ST_FAILED or CH_ST_CLOSED.
//   - A pool runs out when many handshakes are in flight. Each handshake
//     needs a deadline of the caller's, so a peer that stops halfway
//     gives its buffer back when ch_tcp_close ends it.
// The buffer never holds a key: the keys stay in ch_tcp, which chapulin
// wipes too.
//
// The session calls no callback of cfg's: cfg.send and cfg.recv are NULL,
// and each init call refuses one that is not (INV-28). The caller hands
// ch_read_in_place the bytes it holds, and the call opens one whole
// record where it lies. The caller writes its plaintext where its records
// will go, and ch_seal_in_place seals it there (below,
// docs/decisions.md 248). ch_read, ch_write, ch_write_parts, ch_close and
// ch_fail, the calls of tls.h that copy and send, are
// TRANSPORT=tcp-blocking calls alone.
//
// Closing takes two calls, one per direction. The peer's close_notify
// closes the peer's direction alone (RFC 9846 §6.1): the
// ch_read_in_place that reads it returns CH_ECLOSED and wipes the read
// key, and every later one returns CH_ECLOSED and reads nothing. The
// write direction stays open, so ch_tcp_state still reports
// CH_ST_CONNECTED and ch_seal_in_place still seals. The caller closes its
// own direction with ch_close_out, which writes this side's close_notify
// into the caller's storage as one record and leaves the session
// CH_ST_CLOSED, whichever side closed first. ch_tcp_close after it is
// safe. A KeyUpdate whose sender asked for an answer gets it from the next
// ch_seal_in_place, before that call's data (RFC 9846 §4.7.3,
// docs/decisions.md 138).
//
// Result codes match quic.h's meanings. CH_OK means the call did what it
// says. CH_EINVAL from ch_tcp_init means it refused the configuration,
// staged nothing and left the session failed until the next init; from
// every other call, that the caller called out of order and nothing
// changed. CH_ECAP from ch_tcp_out means the caller's buffer was short,
// nothing was consumed, and the same call may run again with a larger
// one, and from ch_seal_in_place the same, unless the call says the
// session failed (below). CH_EPROTO from a call on a session that failed
// or closed, and from ch_read_in_place, ch_seal_in_place, ch_close_out or
// ch_fail_out before the handshake completes, changes nothing either.
// Every other code leaves the session dead.
//
// The call that fails emits its failure's alert the way it emits its
// other records. ch_tcp_in stages it as one record, which ch_tcp_out
// hands over on the failed session. ch_srv_tcp_in pushes it through
// cfg.srv.on_record_out before it returns (srv_tcp_nonblocking.h).
// ch_read_in_place writes it into the caller's reply, and
// ch_seal_in_place into the caller's side buffer. The caller holds no key,
// so the
// driver seals the record itself: under this side's write key once there
// is one, because RFC 9846 §6 protects an alert under the current write
// key, and in the clear before that. A client installs its write key
// right after the ServerHello, and a server right after it has sent its
// own. So a handshake failure before that key emits REC_HDR + 2 bytes, and
// one after it CH_ALERT_RECORD_LEN bytes (tls.h). ch_alert_sent names the
// alert in every case (alert.h). A failure on the peer's fatal alert
// emits none, and ch_alert_sent reads 0 then (RFC 9846 §6.2).
#ifndef CH_TCP_NONBLOCKING_H
#define CH_TCP_NONBLOCKING_H
#ifdef CH_TRANSPORT_TCP_NONBLOCKING

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "result.h"
#include "session_report.h"
#include "session_storage.h"

// The client's driver, the three calls below, is declared only in an
// object with a client, which alone defines it (tcp_nonblocking.c). A
// ROLE=server object declares srv_tcp_nonblocking.h's in its place, so
// a server that calls one of these fails to compile rather than to link.
#if !defined(CH_ROLE_SERVER) || defined(CH_ROLE_BOTH)
// Prepares a session and stages its ClientHello. It reads the
// configuration and draws this connection's key share, and it sends
// nothing: the caller collects the hello with ch_tcp_out.
//
// Returns CH_EINVAL for every configuration ch_connect refuses (tls.h)
// but the I/O callbacks, and for a cfg.send or a cfg.recv that is not
// NULL. No call of this mode sends through cfg.send or reads through
// cfg.recv, so either names a callback nothing calls, and the refusal says
// so at configuration time (INV-28).
//
// A refusal zeroes r, so nothing is staged, and ch_tcp_state answers
// CH_ST_FAILED until the next ch_tcp_init. It keeps the values ch_epoch,
// ch_epoch_seen and ch_epoch_status report, as a CA build's epoch check wrote them,
// the three fields ch_connect leaves (docs/ca.md): a ticket that the
// stored epoch retired is one of those refusals, and epoch_status then
// reads CH_EPOCH_REVOKED, as it does after ch_connect.
//
// Requires: r and cfg are not NULL, and cfg outlives the session.
int CH_MUST_USE ch_tcp_init(ch_tcp *r, const ch_cfg *cfg);

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
// nothing, while a record ch_tcp_out has not handed over yet is
// staged: the peer cannot have answered it. Returns CH_EPROTO without
// reading a byte on a session that failed or closed. Every other code
// leaves the session dead, with the alert its failure chose staged for
// ch_tcp_out unless the failure was the peer's fatal alert (above). A
// record delivered here once ch_tcp_state reports CH_ST_CONNECTED
// fails the session too, and the call reads none of its bytes: that
// record is ch_read_in_place's.
int CH_MUST_USE ch_tcp_in(ch_tcp *r, uint8_t *p, size_t n, size_t *consumed);

// Collects bytes the caller must send. out_len is 0 when nothing is
// owed, which is the normal answer while waiting for the peer. A caller
// whose buffer is smaller than the staged record gets what fits and
// calls again; the record is finished when out_len is 0.
//
// After a failure in ch_tcp_in the staged record is that failure's
// alert, and this call hands it over on the failed session the same way,
// in as many calls as the caller's buffer needs. Once its last byte is
// out, the next call returns CH_EINVAL. The caller sends those bytes and
// then closes the connection.
//
// Returns CH_ECAP only when cap is 0, because any other capacity makes
// progress. Returns CH_EINVAL on a session that failed or closed and
// holds no staged byte. Neither changes the session, and neither writes
// *out_len.
int CH_MUST_USE ch_tcp_out(ch_tcp *r, uint8_t *out, size_t cap, size_t *out_len);
#endif

// CH_ST_START while the handshake runs, CH_ST_CONNECTED once it is done
// and the session is ready for ch_read_in_place and ch_seal_in_place,
// CH_ST_FAILED after an error, and CH_ST_CLOSED after ch_close_out or
// ch_tcp_close (session.h). The peer's close_notify leaves it at
// CH_ST_CONNECTED, because ch_seal_in_place still works; ch_read_closed
// says it arrived.
uint8_t ch_tcp_state(const ch_tcp *r);

// Returns the ch_tls inside r, which ch_read_in_place, ch_seal_in_place,
// ch_writable_len, ch_close_out, ch_fail_out, alert.h's calls and
// session_report.h's calls take. Requires: r is not NULL. It cannot fail
// and changes nothing.
ch_tls *ch_tcp_tls(ch_tcp *r);

// Wipes every secret and marks the session dead. Safe on a session that
// already failed, where it also drops an alert record ch_tcp_out has
// not handed over. A session whose handshake still runs gives cfg.buf
// back here, wiped, as a failed one does. It writes nothing, so a
// connected caller calls ch_close_out on ch_tcp_tls(r) first, which writes
// this side's close_notify.
void ch_tcp_close(ch_tcp *r);

// The length of the TLS record at the front of p, its 5-byte header
// included, or 0 while p holds less than that whole record. It reads the
// header's length field, p[3] and p[4], and no byte at or past p[n]. A
// caller that hands ch_tcp_in or ch_srv_tcp_in whole records asks it of
// the bytes it holds, and waits for more bytes when it answers 0. It
// reads no session, so either role asks it. ch_read_in_place needs no
// such answer: it finds the end of each record itself.
//
// A header whose length field is above 2^14 + 256 names a record no peer
// may send: RFC 9846 §5.2 caps the field there (rfc9846.txt:3595-3596). The
// answer for such a header is REC_HDR, the header alone, as soon as p holds
// it. ch_read_in_place reads those five bytes, refuses the length and fails
// the session, so the caller does not wait for a body the peer must not
// send. So every answer is 0 or a length from REC_HDR to n, and the
// largest is REC_HDR + 2^14 + 256, 16,645 bytes. A record of up to that
// length that cfg.buf_len cannot hold is ch_read_in_place's to refuse once
// it is whole; a peer that keeps to this endpoint's record_size_limit
// sends records of at most cfg.buf_len bytes.
size_t ch_tcp_whole_len(const uint8_t *p, size_t n);

// What one ch_read_in_place did, in bytes of the caller's p. consumed:
// the bytes at the front of p the call took, which the caller drops.
// pt_off and pt_len: where the plaintext of an application data record
// lies in p, which the call opened there; pt_len is 0 for a record that
// carries no data, a ticket, a KeyUpdate or an empty record, and pt_off is
// 0 then. reply_len: the bytes the call wrote into reply, the alert of
// its failure or 0.
typedef struct {
    size_t consumed;
    size_t pt_off;
    size_t pt_len;
    size_t reply_len;
} ch_read_result;

// Opens the next record in p, the n bytes the caller holds, where it
// lies: the plaintext replaces the ciphertext, REC_HDR bytes after the
// record's start, and no byte is copied out (docs/decisions.md 247). It
// reads at most one record, except to finish a post-handshake message
// (below), so the caller calls it again for each record.
//
// p is not const: the call writes the bytes of each record it opens. A
// record that does not open, because its tag does not match or its
// fields are wrong, has every byte wiped, so no unverified plaintext
// stays in p. A call that fails for any other reason wipes the bytes of
// the records it opened too. Bytes past the records the call reads stay
// as they were.
//
// A post-handshake message, a NewSessionTicket or a KeyUpdate, may arrive
// in parts across records (RFC 9846 §5.1). The call then opens every
// whole record p holds until the message is whole, and joins the parts
// where they lie. When p ends first it returns CH_TCP_AGAIN: the session
// holds no copy, so the caller presents the same bytes again, unchanged,
// at the front of its next p, with more bytes after them. The records of
// one message take at most cfg.buf_len bytes of p together, and a message
// that needs more fails with unexpected_message.
//
// Returns:
//   - CH_OK when the call took one record, or the records that finished a
//     message: result->consumed is above 0, and pt_off and pt_len name the
//     plaintext, if any.
//   - CH_TCP_AGAIN when p holds less than a whole record after the bytes
//     a message in parts already holds. result->consumed is 0. It is not
//     an error, and the session stays connected.
//   - CH_ECLOSED once the peer's direction is closed: the call that reads
//     the peer's close_notify consumes it and wipes the read key, and
//     every later call reads nothing. It returns CH_ECLOSED after
//     ch_close_out as well. It is not an error.
//   - CH_EINVAL for a NULL result or reply, a reply_cap below
//     CH_ALERT_RECORD_LEN, a NULL p with n above 0, or an n below the
//     bytes a message in parts holds. CH_EPROTO on a session that is not
//     connected. Neither reads p or changes the session.
//   - Every other code leaves the session dead, with the alert its
//     failure chose in reply, CH_ALERT_RECORD_LEN bytes that result's
//     reply_len counts, and ch_alert_sent names it. The caller sends
//     those bytes after every record it sealed before this call. The
//     peer's fatal alert is the exception: the call returns CH_EPROTO and
//     writes nothing, and ch_alert_received names the alert (RFC 9846
//     §6.2). CH_KEY_UPDATE_LIMIT says the peer sent one KeyUpdate past
//     CH_KEY_UPDATE_RUN_MAX in a row (public_sizes.h, docs/decisions.md
//     138).
//
// A KeyUpdate that asks for an answer gets it from the next
// ch_seal_in_place (RFC 9846 §4.7.3), so this call writes nothing into
// reply for it.
//
// Requires: t was connected by ch_tcp_out or ch_srv_tcp_in. The caller
// reads nothing of p's records while the call runs.
int CH_MUST_USE ch_read_in_place(ch_tls *t, uint8_t *p, size_t n, uint8_t *reply, size_t reply_cap,
                                 ch_read_result *result);

// What one ch_seal_in_place wrote. records_len: the bytes of sealed
// records at the front of buf. side_len: the bytes of the one record the
// call wrote into side, 0 when it wrote none. The caller sends side's
// record first and then buf's records, in that order, after every record
// it sealed before this call.
typedef struct {
    size_t records_len;
    size_t side_len;
} ch_seal_result;

// Seals n bytes of application data where they lie (docs/decisions.md
// 248). The caller writes the plaintext in one run at buf + REC_HDR, in
// a buffer of cap bytes. The call cuts the run into records of at most
// the smaller of the peer's record_size_limit and CH_TX_PT bytes, as
// ch_write does on the other transport (INV-38). It moves each record's
// plaintext after the first one forward by REC_OVERHEAD bytes for each
// record before it, then seals each record in its place. So buf's first
// n + ceil(n / limit) * REC_OVERHEAD bytes become the records, each
// header before its ciphertext, and the caller sends them from buf.
// ch_writable_len(t, cap) is the largest n whose records fit cap.
//
// The call writes one record into side, which holds side_cap bytes, when
// a KeyUpdate goes before the data: one that answers the peer's request
// (RFC 9846 §4.7.3, docs/decisions.md 138), or one that retires an AES-GCM
// write key that cannot seal every record of this write before its
// ceiling (record.h, RFC 9846 §5.5). Either way the KeyUpdate goes first,
// CH_KEY_UPDATE_RECORD_LEN bytes under the old key, and every record of
// the write goes out under the next key. One KeyUpdate serves both.
//
// The call seals every record or none. Returns:
//   - CH_OK when it sealed them all, or for an n of 0, which seals and
//     writes nothing, an owed KeyUpdate included.
//   - CH_EINVAL for a NULL result or side, a side_cap below
//     CH_KEY_UPDATE_RECORD_LEN, or a NULL buf with n above 0. CH_EPROTO on
//     a session that is not connected. CH_ECAP for an n above
//     ch_writable_len(t, cap). None of the three writes buf or side or
//     changes the session.
//   - CH_ECAP with the session failed when no key can seal the write: a
//     KeyUpdate is due and this side sent 2^48 - 1 already, the most RFC
//     9846 §4.7.3 lets it send, or the write key's sequence number would
//     wrap (RFC 9846 §5.3). side then holds the
//     internal_error alert, CH_ALERT_RECORD_LEN bytes that side_len
//     counts, and ch_alert_sent names it. buf holds the plaintext as the
//     caller wrote it. ch_tcp_state tells this result from the one above.
//
// Requires: t was connected by ch_tcp_out or ch_srv_tcp_in. The caller
// reads and writes no byte of buf's first cap bytes while the call runs.
int CH_MUST_USE ch_seal_in_place(ch_tls *t, uint8_t *buf, size_t cap, size_t n, uint8_t *side,
                                 size_t side_cap, ch_seal_result *result);

// Closes this side's direction: writes this side's close_notify into out,
// one record of CH_ALERT_RECORD_LEN bytes sealed under the write key, and
// its length to *out_len, then wipes every key and leaves the session
// CH_ST_CLOSED (RFC 9846 §6.1). It writes no KeyUpdate first, even when an
// answer to the peer's request is owed: RFC 9846 §4.7.3 owes that answer
// before application data alone, and none follows the close. The caller
// sends the record after every record it sealed before this call.
//
// Returns CH_OK, or CH_ECAP when the write key had no sequence number left
// (RFC 9846 §5.3), which closes the session too with *out_len 0. Returns
// CH_EINVAL for a NULL out or out_len or a cap below CH_ALERT_RECORD_LEN,
// and CH_EPROTO on a session that is not connected. Neither changes the
// session or writes out, and CH_EINVAL writes no *out_len either; every
// other answer writes it. A session whose handshake still runs, or that
// failed, ends with ch_tcp_close.
int CH_MUST_USE ch_close_out(ch_tls *t, uint8_t *out, size_t cap, size_t *out_len);

// ch_fail on this transport: fails a connected session with the fatal
// alert description names, for an error the caller found itself. It
// writes the alert into out, one record of CH_ALERT_RECORD_LEN bytes
// sealed under the write key, and its length to *out_len, records it for
// ch_alert_sent, wipes every key and leaves the session CH_ST_FAILED. The
// caller sends the record after every record it sealed before this call.
//
// description is one of the error alerts of RFC 9846 §6.2
// (rfc9846.txt:3796-3823): every AlertDescription but close_notify (0)
// and user_canceled (90). Returns CH_EINVAL for any other value, a NULL
// out or out_len, or a cap below CH_ALERT_RECORD_LEN, and CH_EPROTO on a
// session that is not connected. Neither changes the session or writes
// out, and CH_EINVAL writes no *out_len either; every other answer writes
// it. Otherwise the session fails, and the call returns CH_OK, or CH_ECAP
// with *out_len 0 when the write key had no sequence number left. It writes no
// KeyUpdate first, as ch_close_out writes none (docs/decisions.md 164).
int CH_MUST_USE ch_fail_out(ch_tls *t, uint8_t description, uint8_t *out, size_t cap,
                            size_t *out_len);

#endif // CH_TRANSPORT_TCP_NONBLOCKING
#endif
