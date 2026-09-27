// What ended a session: the fatal alert this side's failure chose, and the
// fatal alert the peer sent (RFC 9846 §6.2). Every object holds a ch_tls
// and exports both calls, whatever its transport and role, so tls.h and
// quic.h both include this header: a tcp-blocking session passes its
// ch_tls, a tcp-nonblocking one &r->t (tcp_nonblocking.h) and a QUIC one
// &q->t (quic.h). Neither value is secret: the peer sent or reads each one.
#ifndef CH_ALERT_H
#define CH_ALERT_H

#include <stdint.h>

#include "session.h"

// Every object exports both calls, so their symbol names carry the
// object's transport, as ch_ticket_obfuscated_age's do (ticket.h): an
// image that links a tcp-nonblocking object and a QUIC object holds one
// of each (docs/decisions.md 61 and 75).
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#define ch_alert_sent ch_alert_sent_quic_nonblocking
#define ch_alert_received ch_alert_received_quic_nonblocking
#elif defined(CH_TRANSPORT_TCP_NONBLOCKING)
#define ch_alert_sent ch_alert_sent_tcp_nonblocking
#define ch_alert_received ch_alert_received_tcp_nonblocking
#else
#define ch_alert_sent ch_alert_sent_tcp_blocking
#define ch_alert_received ch_alert_received_tcp_blocking
#endif

// The description of the fatal alert this side's failure chose, and 0
// while no failure has chosen one. The call that fails the session writes
// it, and where that call runs decides who sends the alert:
//
// - ch_connect, ch_srv_accept, ch_read and ch_write send it themselves,
//   through cfg.send, in the clear before any key and protected after.
//   The send is best effort: a transport that failed may not carry it.
// - ch_record_in and ch_srv_record_in send nothing while the handshake
//   runs, and ch_record_alert names the same description for the caller
//   to send (tcp_nonblocking.h).
// - A QUIC session reports what ch_quic_alert reports, and
//   ch_quic_error_code turns it into the code the caller puts in
//   CONNECTION_CLOSE (quic.h).
//
// It stays 0 when the session failed on the peer's fatal alert, because
// this side then sends none (ch_alert_received below). It stays 0 when an
// init call refused the configuration, which sends nothing, and after
// ch_close, because a close_notify is not a fatal alert.
//
// It reads one field of t and changes nothing, so a caller may ask in any
// state, and after ch_close, ch_record_close or ch_quic_close, which keep
// the field.
uint8_t ch_alert_sent(const ch_tls *t);

// The description of the fatal alert the peer sent, and 0 when none
// arrived. A record of the alert type holds exactly one alert, 2 bytes,
// and every description but close_notify and user_canceled is a fatal
// alert, whatever the level byte says (RFC 9846 §5.1 and §6,
// rfc9846.txt:3475-3478 and 3779-3782). One that arrives in the handshake,
// in the clear or protected, or protected after the handshake, ends the
// session. The call that read it returns CH_EPROTO, wipes the keys, marks
// the session failed and sends nothing, because §6.2 has both sides close
// the connection at once (rfc9846.txt:3890-3893). ch_alert_sent then reads
// 0, and in a tcp-nonblocking session ch_record_alert does too.
//
// The handshake reads an alert in the clear even once this side reads
// protected records, because a peer that failed before it installed its
// own write key sends one that way: a client that could not use the
// ServerHello, to a server that already reads protected records. Nothing
// authenticates such an alert, so its description is what the record
// says and no more.
//
// A record of the alert type that is not one 2-byte alert is not an alert
// the peer sent: the call that read it answers with decode_error, which
// ch_alert_sent reports, and this call reads 0. It reads 0 after the two
// closure alerts too (§6.1): close_notify, which closes the peer's
// direction (tls.h), and user_canceled, which a connected session reads
// past.
//
// A QUIC session reads 0 always: QUIC carries no alert record (RFC 9001
// §4.8), and a peer's CONNECTION_CLOSE is the caller's to read. Like
// ch_alert_sent, the call changes nothing, and a caller may ask in any
// state.
uint8_t ch_alert_received(const ch_tls *t);

#endif
