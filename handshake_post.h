// The two handshake messages a server may send after the handshake
// finishes, on a live authenticated session: NewSessionTicket and
// KeyUpdate (RFC 9846 §4.7). They ride handshake records, so ch_read
// meets them while the application is only asking for bytes.
//
// This is the last attacker-facing parser in the library. Everything it
// reads arrives decrypted from a peer that authenticated, which makes it
// less exposed than the handshake flight and no less parsed.
//
// Under CH_TRANSPORT_QUIC they ride CRYPTO frames at the 1-RTT level
// and the driver's HSQ_STEP_COMPLETE step meets them, one whole message
// per step. Only the NewSessionTicket survives there: RFC 9001 §6 makes
// a TLS KeyUpdate a connection error (rfc9001.txt:1566-1568) and §4.4
// makes a post-handshake CertificateRequest one too
// (rfc9001.txt:735-738).
#ifndef CH_HANDSHAKE_POST_H
#define CH_HANDSHAKE_POST_H

#include <stddef.h>
#include <stdint.h>

#include "session.h"

#ifndef CH_TRANSPORT_QUIC
// Reads whole post-handshake messages, starting from pt_len plaintext
// bytes already in cfg.buf and pulling further records when one message
// is fragmented across them. Returns CH_OK once the run is consumed, or
// an error; the caller turns the error into an alert.
//
// A TRANSPORT=quic build declares neither this call nor the KeyUpdate
// handler under it. There is no record run to drain, and a TLS
// KeyUpdate message is a connection error of type 0x010a on that
// transport (RFC 9001 §6, rfc9001.txt:1566-1568), so the only
// post-handshake message it accepts is a NewSessionTicket and
// hspost_take_ticket is the one way in.
int hspost_read(ch_tls *t, size_t pt_len);
#endif

#ifdef CH_TRANSPORT_QUIC
// Handles one whole NewSessionTicket the caller has already read and
// whose type it has already checked (RFC 9846 §4.7.1). It parses the
// ticket, derives the resumption PSK and hands it to cfg.on_ticket,
// which is what the TLS build does; resumption over QUIC is the same
// external PSK it is over TCP.
//
// It reads the ticket's extension block rather than skipping it, which
// is the one difference from the TLS path. RFC 9001 §4.6.1 repurposes
// early_data's max_early_data_size as the sentinel 0xffffffff, which
// says the server accepts QUIC 0-RTT, and a server that does not accept
// 0-RTT omits the extension (rfc9001.txt:799-802). This client offers
// no 0-RTT, so both shapes are accepted and neither changes what it
// sends; any other value is refused, because §4.6.1 puts an
// unconditional client MUST on that (rfc9001.txt:808-809).
//
// Requires: t is a live connected session; body points at n readable
// bytes, which are the message past its 4-byte handshake header;
// alert and error_code are not NULL. It writes them only on the
// CH_EPROTO return below.
//
// Returns CH_OK when the ticket reached cfg.on_ticket, and also when it
// was dropped without one: cfg.on_ticket NULL, a nonce longer than
// SHA256_LEN, or an identity longer than CH_TICKET_ID_MAX. A ticket a
// later ClientHello could not resend is dropped silently rather than
// surfaced, the TLS rule kept unchanged.
//
// Returns CH_EPROTO, writes ALERT_ILLEGAL_PARAMETER to *alert and 0x0a,
// PROTOCOL_VIOLATION, to *error_code when the ticket carries an
// early_data extension naming any max_early_data_size but 0xffffffff.
// The code is what goes on the wire in CONNECTION_CLOSE; the alert
// never leaves this object, because QUIC carries no TLS alert record,
// and ch_quic_alert reports it for a log.
//
// Returns CH_EPROTO and writes ALERT_DECODE_ERROR to *alert, leaving
// *error_code alone, for a body that does not parse or does not fill
// exactly. ch_quic_error_code then reports 0x0100 plus that alert,
// which is how RFC 9001 §4.8 carries a TLS alert.
int hspost_take_ticket(ch_tls *t, const uint8_t *body, size_t n, uint8_t *alert,
                       uint64_t *error_code);
#endif

#endif
