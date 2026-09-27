// The two handshake messages a server may send after the handshake
// finishes, on a live authenticated session: NewSessionTicket and
// KeyUpdate (RFC 9846 §4.7). They ride handshake records, so ch_read
// meets them while the application is only asking for bytes.
//
// This is the last attacker-facing parser in the library. Everything it
// reads arrives decrypted from a peer that authenticated, which makes it
// less exposed than the handshake flight and no less parsed.
//
// Under CH_TRANSPORT_QUIC_NONBLOCKING they ride CRYPTO frames at the 1-RTT level
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

// Whether cfg may offer its ticket, which every client entry asks before
// it sends a byte: ch_connect and ch_record_init through tls.c's
// tlsi_config_ok, and ch_quic_init through quic_config_ok. RFC 9846
// §4.3.11.1 says a client MUST NOT use a ticket older than its
// ticket_lifetime (rfc9846.txt:2572-2574), and §4.6.1 that it MUST NOT use
// one more than 7 days after issuance whatever that lifetime says
// (rfc9846.txt:3259-3261).
//
// So with cfg->resumption set it answers 0 when cfg->ticket_age_ms is above
// cfg->ticket_lifetime_s seconds or above CH_TICKET_LIFETIME_MAX seconds,
// and 1 when it is at or below both. A lifetime of 0 is one the caller did
// not give, because handle_ticket hands on_ticket no ticket with that
// lifetime (ticket.h), and the age is then held to CH_TICKET_LIFETIME_MAX
// alone. An age of 0 is a ticket that arrived this millisecond. So a
// configuration that sets neither field, as every one written before the
// two existed, is refused nothing. Without resumption no ticket is
// offered, and the answer is 1.
//
// The lifetime is capped before it is scaled, so it is at most
// 604,800,000 milliseconds, which a uint32_t holds. The product is then a
// 32-bit multiply, where a 64-bit one is a widening multiply on a 32-bit
// core, which lint-wide-multiply counts.
static inline int hspost_ticket_age_ok(const ch_cfg *cfg) {
    if (!cfg->resumption) {
        return 1;
    }
    uint32_t lifetime_s = CH_TICKET_LIFETIME_MAX;
    if (cfg->ticket_lifetime_s != 0 && cfg->ticket_lifetime_s < lifetime_s) {
        lifetime_s = cfg->ticket_lifetime_s;
    }
    uint32_t lifetime_ms = lifetime_s * 1000U;
    return cfg->ticket_age_ms <= lifetime_ms;
}

#ifndef CH_TRANSPORT_QUIC_NONBLOCKING
// Reads whole post-handshake messages, starting from pt_len plaintext
// bytes already in cfg.buf and pulling further records when one message
// is fragmented across them. Returns CH_OK once the run is consumed.
// Otherwise it fails the session through tlsi_fail with the alert the
// failure owes, and returns the error: unexpected_message, which is what
// a KeyUpdate with bytes after it in its record gets, because RFC 9846
// §5.1 lets no handshake message span the key change a KeyUpdate makes
// (rfc9846.txt:3464-3470), and what a server's session gets for a
// NewSessionTicket, which §4.7.1 gives the server alone to send
// (rfc9846.txt:3194-3196); decode_error for a KeyUpdate whose body is
// not one byte and a NewSessionTicket whose fields do not fill it
// (§6, rfc9846.txt:3785-3788); illegal_parameter for a KeyUpdate whose
// request_update is neither 0 nor 1 (§4.7.3, rfc9846.txt:3362-3365);
// bad_record_mac for a record that does not
// open; and what hsr_refuse_alert chose for an alert record between two
// records of one message, whose error alert is the peer's fatal alert
// and is answered with nothing. A TRANSPORT=tcp-nonblocking
// build also returns CH_RECORD_AGAIN when the next fragment has not
// arrived: the fragment bytes so far stay at the front of cfg.buf,
// t->post_fill counts them, and the caller passes that count back here
// on its next read. It is not an error, and nothing fails.
//
// A TRANSPORT=quic-nonblocking build declares neither this call nor the KeyUpdate
// handler under it. There is no record run to drain, and a TLS
// KeyUpdate message is a connection error of type 0x010a on that
// transport (RFC 9001 §6, rfc9001.txt:1566-1568), so the only
// post-handshake message it accepts is a NewSessionTicket and
// hspost_take_ticket is the one way in.
int hspost_read(ch_tls *t, size_t pt_len);
#endif

#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
// Handles one whole NewSessionTicket the caller has already read and
// whose type it has already checked (RFC 9846 §4.7.1). It parses the
// ticket, derives the resumption PSK and hands it to cfg.on_ticket,
// which is what a TCP build does; resumption over QUIC is the same
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
