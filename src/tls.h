// chapulin public API: a TLS 1.3 client speaking exactly one profile —
// TLS_CHACHA20_POLY1305_SHA256, x25519, ECDHE-PSK (psk_dhe_ke). Zero heap:
// the session struct plus the caller's receive buffer is the entire
// working set. The caller supplies blocking I/O callbacks (bounded by its
// own timeouts) and a random source (rand.h). Configuration and result
// codes live in cfg.h; the session struct in session.h; the two calls
// that report what alert ended a session in alert.h.
#ifndef CH_TLS_H
#define CH_TLS_H

#include "alert.h"
#include "session.h"
#include "session_report.h"

// Runs the full handshake. On CH_OK the session is ready for read/write.
// Any error wipes all key material and leaves the session dead. A
// configuration it refuses returns CH_EINVAL before a byte is sent. A CA
// build's ticket that the stored epoch retired is one of those
// refusals, and ch_tls.epoch_status reads CH_EPOCH_REVOKED after it
// (docs/ca.md). So is a PSK whose identity is not 1 to CH_TICKET_ID_MAX
// bytes (cfg.h), and that bound keeps every ClientHello inside ch_tls.tx.
// Every other error comes from the handshake, which first tries to send
// the alert its failure chose, and ch_alert_sent names it.
// The peer's fatal alert is the exception: the handshake returns
// CH_EPROTO, sends nothing and ch_alert_received names the alert
// (alert.h, RFC 9846 §6.2).
//
// It is declared only where it is defined, in a TRANSPORT=tcp-blocking
// object with a client. A ROLE=server object exports ch_srv_accept in
// its place (srv.h), and a TRANSPORT=tcp-nonblocking one ch_record_init
// (tcp_nonblocking.h), so a firmware that calls ch_connect against
// either fails to compile rather than to link. A
// TRANSPORT=quic-nonblocking object defines no call in this header, and
// no header of that build includes it: quic.h is its API. The calls
// below keep their contracts in both roles, because record.[ch] names
// no side.
#if (!defined(CH_ROLE_SERVER) || defined(CH_ROLE_BOTH)) && !defined(CH_TRANSPORT_TCP_NONBLOCKING)
int CH_MUST_USE ch_connect(ch_tls *t, const ch_cfg *cfg);
#endif

// Sends n bytes as one or more records. Returns CH_OK or an error. It
// keeps working after ch_read has returned 0 for the peer's close_notify.
// On a session that is not connected it returns CH_EPROTO and changes
// nothing: once ch_close has run, once the session has failed, and in a
// TRANSPORT=tcp-nonblocking build while the handshake still runs, which
// that CH_EPROTO leaves running. Every other error, a record it cannot
// seal (CH_ECAP) or a send that fails (CH_EIO), leaves the session dead,
// after it tries to send internal_error, which ch_alert_sent names.
//
// A peer's KeyUpdate that asks for an answer gets it here: before the
// first record of the next write of one byte or more, ch_write sends a
// KeyUpdate record, request_update 0, CH_KEY_UPDATE_RECORD_LEN bytes under
// the old key, and seals the write under the next key (RFC 9846 §4.7.3).
// One answer serves every request ch_read read since this side's last
// KeyUpdate, and a request read at the epoch cap below gets none. A
// session that never writes again sends none, and ch_close sends its
// close_notify under the old key (docs/decisions.md 138).
//
// A write key that runs AES-GCM, which only a SUITE=aesgcm build has,
// seals at most REC_AES_GCM_RECORDS_MAX records (record.h, RFC 9846
// §5.5). When the next record of a write would be the last of those,
// ch_write sends a KeyUpdate record in its place, the same record, and one
// KeyUpdate is both the answer and the step past the ceiling. RFC 9846
// §4.7.3 lets a sender send 2^48 - 1 KeyUpdates, and a key at its ceiling
// after that many cannot be replaced: that write returns CH_ECAP and
// leaves the session dead, after it tries to send internal_error under the
// old key.
int CH_MUST_USE ch_write(ch_tls *t, const uint8_t *p, size_t n);

// One part of the plaintext ch_write_parts sends: pt_len bytes at pt. The
// caller owns the bytes. pt may be NULL when pt_len is 0.
typedef struct {
    const uint8_t *pt;
    size_t pt_len;
} ch_part;

// Sends the part_count parts as one run of plaintext, each part after the
// one before it, in the records ch_write sends for that run in one buffer:
// a record holds bytes of every part it crosses, and a part may cross
// records. Its results, its KeyUpdate records and its failures are
// ch_write's, and ch_write is this call over one part. ch_writable_len
// counts the parts' lengths together. So the caller seals a header and a
// payload that sit apart in its memory without a copy of its own:
// ch_write copies each record's plaintext once into ch_tls.tx anyway, and
// this call copies it there from the parts. parts may be NULL when
// part_count is 0. A part of 0 bytes adds nothing (docs/decisions.md 167).
int CH_MUST_USE ch_write_parts(ch_tls *t, const ch_part *parts, size_t part_count);

// The most plaintext one ch_write seals into cap bytes of records, so a
// caller whose send takes at most cap bytes per call knows how much to
// pass. ch_write cuts its input into records of at most the smaller of
// t->peer_limit and CH_TX_PT bytes of plaintext, the send limit INV-38
// states, and each record costs REC_OVERHEAD bytes more: the 5-byte
// header, the inner content type and the AEAD tag. So n bytes go out as
// ceil(n / limit) records, n + ceil(n / limit) * REC_OVERHEAD bytes in all,
// and this is the largest n whose records fit cap. It is 0 when cap
// cannot hold a record of one byte, and 0 for a session whose peer_limit
// is 0, which no connected session has.
//
// When ch_write sends one KeyUpdate record among those records,
// CH_KEY_UPDATE_RECORD_LEN bytes (above), this counts it: first, while the
// answer to a peer's request is owed, and under an AES-GCM write key where
// the records would take the key to its ceiling. It counts one KeyUpdate
// and no second: under an AES-GCM key it returns at most the plaintext of
// the records the key has left and REC_AES_GCM_RECORDS_MAX - 1 records
// under the next key, so a write it sizes crosses the ceiling once at
// most. At the smallest record a peer may ask for, 63 bytes of plaintext,
// that is still more than a gigabyte.
//
// It reads t->peer_limit, whether an answer is owed, and under
// SUITE=aesgcm the write key's suite and sequence number, and nothing
// else. ch_write still refuses a session that is not connected, whatever
// this returns.
size_t ch_writable_len(const ch_tls *t, size_t cap);

// The wire length of one sealed alert record, 24 bytes: REC_OVERHEAD and
// the 2-byte alert, a level and a description (RFC 9846 §6). ch_close sends
// one, and a ch_read that fails sends one, unless the peer's fatal alert
// is what failed it: that one it answers with nothing. A tcp-nonblocking
// handshake that fails after this side's write key is installed emits one
// through ch_record_out or cfg.srv.on_record_out, and one that fails
// before it emits the alert in the clear, REC_HDR + 2 bytes
// (tcp_nonblocking.h).
#define CH_ALERT_RECORD_LEN (REC_OVERHEAD + 2)

// The wire length of one sealed KeyUpdate record, 27 bytes: REC_OVERHEAD,
// the 4-byte handshake header and the 1-byte request_update (RFC 9846
// §4.7.3). ch_write sends one before its first record while an answer to
// the peer's request is owed, and one as the last record an AES-GCM write
// key seals, and one record serves both (above). ch_read sends none: the
// only record it sends is the alert of a failure.
#define CH_KEY_UPDATE_RECORD_LEN (REC_OVERHEAD + 4 + 1)

// Receives into p (n >= 1), returning the byte count (>0), 0 at the end
// of the peer's stream, or an error. Handles NewSessionTicket and
// KeyUpdate internally. A KeyUpdate moves the read key, and one that asks
// for an answer leaves it owed to the next ch_write (above).
//
// It reads at most CH_KEY_UPDATE_RUN_MAX KeyUpdates in a row (session.h):
// only a record of application data with one byte or more ends a run, in
// this call or an earlier one. The next KeyUpdate returns
// CH_KEY_UPDATE_LIMIT (result.h) and leaves the session dead, after it
// tries to send unexpected_message, which ch_alert_sent names. It refuses
// that KeyUpdate before it moves the read key. One call also fails with
// CH_EPROTO and unexpected_message once it has read CH_QUIET_CAP records
// that give no data (session.h). So a run that holds more than
// CH_QUIET_CAP - CH_KEY_UPDATE_RUN_MAX - 1 other such records in one call,
// 15 at the default cap, fails there first.
//
// An n of 0 returns CH_EINVAL and changes nothing. A closed session
// returns 0. A session that is not connected returns CH_EPROTO and
// changes nothing: one that failed, and in a TRANSPORT=tcp-nonblocking
// build one whose handshake still runs, which keeps running. Every other
// error leaves the session dead, after it tries to send the alert its
// failure chose, which ch_alert_sent names. The peer's fatal alert is the
// exception: it returns CH_EPROTO and sends nothing, and
// ch_alert_received names the alert (alert.h, RFC 9846 §6.2). An alert
// record that is not one 2-byte alert is answered with decode_error.
//
// The end of the peer's stream is its close_notify, which closes the
// peer's direction and no other (RFC 9846 §6.1). The ch_read that reads
// it returns 0, wipes the read key and sends nothing. The session stays
// CH_ST_CONNECTED with ch_tls.read_closed set, so ch_write still sends,
// and ch_close sends this side's close_notify. Every later ch_read
// returns 0 without calling cfg.recv, so a record the peer sends after
// its close_notify is never read, which is how §6.1's rule to ignore it
// is kept. ch_read returns 0 after ch_close as well.
//
// A TRANSPORT=tcp-nonblocking build may also return CH_RECORD_AGAIN (cfg.h): the
// caller's recv returned 0 at a record boundary, so no record has arrived
// yet. The session stays connected and every record already read has
// been handled, a ticket or a KeyUpdate among them; the caller calls
// ch_read again once it holds the next whole record. tcp_nonblocking.h states
// the recv contract that goes with it.
int CH_MUST_USE ch_read(ch_tls *t, uint8_t *p, size_t n);

#ifdef CH_EXPORTER
// The longest exporter label this build takes, not counting a
// terminator. 32 admits RFC 9266's "EXPORTER-Channel-Binding" at 24 and
// leaves room; the EXPORTER axis sets hkdf.h's own cap to the same
// number and tls.c asserts the two agree.
#define CH_EXPORT_LABEL_MAX 32

// The most bytes one call yields. RFC 9846 §7.5 sets no limit and HKDF
// allows 255 hashes; this is the bound a caller's buffer is checked
// against, sized for the key material a channel binding or a QUIC-style
// secret asks for.
#define CH_EXPORT_MAX 255

// TLS-Exporter (RFC 9846 §7.5): writes out_len bytes bound to label and
// context, from a secret derived when the handshake completed.
//
// label is a NUL-terminated ASCII string the caller chooses, and two
// labels give two unrelated keys from the one session. context may be
// NULL with context_len 0; RFC 9846 §7.5 gives no way to tell an empty
// context from none, so neither does this.
//
// Returns CH_EINVAL when the session is not connected, because the
// secret does not exist until the peer's Finished verifies; when label
// or out is NULL; when label is empty or longer than
// CH_EXPORT_LABEL_MAX; when context_len is non-zero and context is
// NULL; and when out_len is 0 or above CH_EXPORT_MAX. Nothing is
// written on any of those. Otherwise CH_OK.
//
// It reads the session and changes nothing in it, so a caller may call
// it as often as it likes and in any order against ch_read and ch_write.
int CH_MUST_USE ch_export(const ch_tls *t, const char *label, const uint8_t *context,
                          size_t context_len, uint8_t *out, size_t out_len);
#endif

// Sends close_notify (only under live keys) and wipes all key material,
// leaving the session CH_ST_CLOSED. RFC 9846 §6.1 has each side send a
// close_notify before it closes its write direction, and this call is
// what sends this side's, so a caller whose ch_read returned 0 for the
// peer's close_notify still calls it. It sends no KeyUpdate first, even
// when an answer to the peer's request is owed: RFC 9846 §4.7.3 owes that
// answer before application data alone, and none follows the close.
void ch_close(ch_tls *t);

// Fails a connected session with the fatal alert description names, for
// an error the caller found itself: a record header it read before
// ch_read, for example, which RFC 9846 §5.2 answers with record_overflow.
// It sends the alert, protected under the write key, through cfg.send,
// writes it to ch_tls.alert_sent, which ch_alert_sent reads, wipes every
// key and leaves the session CH_ST_FAILED, as a failure of ch_read does.
//
// description is one of the error alerts of RFC 9846 §6.2
// (rfc9846.txt:3796-3823): every AlertDescription but close_notify (0)
// and user_canceled (90). Any other value returns CH_EINVAL and changes
// nothing; ch_close sends close_notify. A session that is not connected
// returns CH_EPROTO and changes nothing: one that failed, one ch_close
// closed, and in a TRANSPORT=tcp-nonblocking build one whose handshake
// still runs. A connected session whose peer sent close_notify is still
// connected, and this call fails it.
//
// Otherwise the session fails whatever the send does, and the call
// returns CH_OK when cfg.send took the whole record, CH_EIO when it did
// not, and CH_ECAP when the write key can seal no more records (record.h).
// It sends no KeyUpdate first, even when an answer is owed, as ch_close
// sends none (docs/decisions.md 164).
int CH_MUST_USE ch_fail(ch_tls *t, uint8_t description);

#endif
