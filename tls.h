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
// Any error wipes all key material and leaves the session dead.
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
// keeps working after ch_read has returned 0 for the peer's close_notify,
// and returns CH_EPROTO once ch_close has run or the session has failed.
int ch_write(ch_tls *t, const uint8_t *p, size_t n);

// Receives into p (n >= 1), returning the byte count (>0), 0 at the end
// of the peer's stream, or an error. Handles NewSessionTicket and
// KeyUpdate internally.
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
// ch_read again once it holds the next whole record. rec.h states the
// recv contract that goes with it.
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
