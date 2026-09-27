// chapulin public API: a TLS 1.3 client speaking exactly one profile —
// TLS_CHACHA20_POLY1305_SHA256, x25519, ECDHE-PSK (psk_dhe_ke). Zero heap:
// the session struct plus the caller's receive buffer is the entire
// working set. The caller supplies blocking I/O callbacks (bounded by its
// own timeouts) and a random source (rand.h). Configuration and result
// codes live in cfg.h; the session struct in session.h.
#ifndef CH_TLS_H
#define CH_TLS_H

#include "session.h"

// Runs the full handshake. On CH_OK the session is ready for read/write.
// Any error wipes all key material and leaves the session dead. A
// configuration it refuses returns CH_EINVAL before a byte is sent, and a
// CA build answers a ticket the stored epoch retired with CH_EAUTH, also
// before a byte is sent (docs/ca.md). Every other error comes from the
// handshake, which first tries to send the alert its failure chose.
//
// A ROLE=server build declares it nowhere: that object exports
// ch_srv_accept in its place (srv.h), so a server firmware that calls
// ch_connect fails to compile rather than to link. The three calls
// below keep their contracts in both roles, because record.[ch] names
// no side.
#if !defined(CH_ROLE_SERVER) || defined(CH_ROLE_BOTH)
int ch_connect(ch_tls *t, const ch_cfg *cfg);
#endif

// Sends n bytes as one or more records. Returns CH_OK or an error. It
// keeps working after ch_read has returned 0 for the peer's close_notify.
// On a session that is not connected it returns CH_EPROTO and changes
// nothing: once ch_close has run, once the session has failed, and in a
// TRANSPORT=tcp-nonblocking build while the handshake still runs, which
// that CH_EPROTO leaves running. Every other error, a record it cannot
// seal (CH_ECAP) or a send that fails (CH_EIO), leaves the session dead.
int ch_write(ch_tls *t, const uint8_t *p, size_t n);

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
// It reads t->peer_limit and nothing else. ch_write still refuses a
// session that is not connected, whatever this answers.
size_t ch_writable_len(const ch_tls *t, size_t cap);

// The wire length of one sealed alert record, 24 bytes: REC_OVERHEAD and
// the 2-byte alert, a level and a description (RFC 9846 §6). ch_close sends
// one, and a ch_read that fails sends one.
#define CH_ALERT_RECORD_LEN (REC_OVERHEAD + 2)

// The wire length of one sealed KeyUpdate record, 27 bytes: REC_OVERHEAD,
// the 4-byte handshake header and the 1-byte request_update (RFC 9846
// §4.7.3). ch_read sends one for each KeyUpdate whose sender asked for an
// answer, so a record that carries several KeyUpdate messages gets several,
// and a failure in the same call adds one alert record.
#define CH_KEY_UPDATE_RECORD_LEN (REC_OVERHEAD + 4 + 1)

// Receives into p (n >= 1), returning the byte count (>0), 0 at the end
// of the peer's stream, or an error. Handles NewSessionTicket and
// KeyUpdate internally.
//
// An n of 0 returns CH_EINVAL and changes nothing. A closed session
// returns 0. A session that is not connected returns CH_EPROTO and
// changes nothing: one that failed, and in a TRANSPORT=tcp-nonblocking
// build one whose handshake still runs, which keeps running. Every other
// error leaves the session dead, after it tries to send the alert its
// failure chose.
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
int ch_read(ch_tls *t, uint8_t *p, size_t n);

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
int ch_export(const ch_tls *t, const char *label, const uint8_t *context, size_t context_len,
              uint8_t *out, size_t out_len);
#endif

// Sends close_notify (only under live keys) and wipes all key material,
// leaving the session CH_ST_CLOSED. RFC 9846 §6.1 has each side send a
// close_notify before it closes its write direction, and this call is
// what sends this side's, so a caller whose ch_read returned 0 for the
// peer's close_notify still calls it.
void ch_close(ch_tls *t);

#endif
