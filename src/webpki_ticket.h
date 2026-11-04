// Resumption for a TRUST=webpki client (docs/webpki.md, "Resumption").
//
// A resumed handshake authenticates the server by the PSK alone: the
// server presents no certificate, so the client checks no chain and no
// hostname. RFC 9846 §4.7.1 therefore lets a client resume only when the
// new server_name is valid for the certificate of the original session
// (rfc9846.txt:3222-3224). These calls hold that rule. Each ticket
// carries a binding to the hostname, the anchors and the SPKI pins of the
// session that received it, and ch_connect, ch_record_init and
// ch_quic_init refuse a ticket whose binding does not match the
// configuration presenting it.
//
// The binding is an HMAC-SHA256 keyed by the ticket's own PSK. The key
// ties it to one ticket: a binding copied from another ticket fails,
// so a caller that stores tickets under the wrong hostname gets
// CH_EINVAL rather than a session with a server it did not name.
#ifndef CH_WEBPKI_TICKET_H
#define CH_WEBPKI_TICKET_H
#ifdef CH_TRUST_WEBPKI

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"

// SHA-256 over what a ticket is bound to, in this order:
//  - hostname_len as 8 big-endian bytes, then the hostname with each
//    ASCII capital letter written in lower case, because the chain walk
//    matches names without case (RFC 6125 §6.4.1, webpki_name.c);
//  - anchor_count as 8 big-endian bytes;
//  - for each anchor in array order: name_len, name, spki_len and spki,
//    each length as 8 big-endian bytes;
//  - spki_pin_count as 8 big-endian bytes, then each pin's SHA256_LEN
//    bytes in array order.
// A configuration of SPKI pins alone hashes a hostname_len and an
// anchor_count of 0. Every input is public, so the hash is too.
//
// cpu is the session's ch_cfg.cpu, which CH_CFG_CPU gives (cpu.h). In a
// host object the hash runs on the SHA-256 instructions when cpu holds
// CH_CPU_CONSTANT_TIME_SHA256, and on sha256.c otherwise (sha256.h). A
// device object holds one SHA-256 and reads no value. Both paths write
// the same bytes, so a ticket bound under one value resumes under any
// other (docs/decisions.md 132).
//
// Requires: cfg->hostname holds hostname_len bytes, cfg->anchors holds
// anchor_count entries whose pointers hold their lengths, and
// cfg->spki_pins holds spki_pin_count pins, which the webpki config
// rules check before any caller runs this. In a host object, cpu holds
// CH_CPU_CONSTANT_TIME_SHA256 only on a CPU with the SHA-256
// instructions (sha256.h). The library passes a session's value, which
// cpu_value_ok accepted. A value of 0 runs sha256.c.
void webpki_ticket_config_hash(uint32_t cpu, const ch_cfg *cfg, uint8_t out[SHA256_LEN]);

// Whether a session under cfg takes the tickets its server sends: whether
// cfg->on_ticket is set. Every init call writes the answer in
// ch_tls.takes_tickets, and writes ch_tls.ticket_config_hash only when
// the answer is 1. In any other session that field stays all zero, and
// handshake_post.c gives a ticket to no one. This is true also when the
// caller sets on_ticket in the session after the init call. The init
// call of a session that takes no tickets hashes the configuration only
// to check a ticket the session presents, in webpki_resumption_ok
// (docs/decisions.md 132).
int webpki_takes_tickets(const ch_cfg *cfg);

// The binding a ticket carries: HMAC-SHA256 keyed by the ticket's PSK,
// the psk_len bytes at psk, over the label "chapulin webpki ticket" and
// the hash above. The binding stays SHA-256 whatever hash the PSK came
// from, because it is this client's own check and no protocol value. cpu
// picks the path as for the hash above. The key is secret, and the
// SHA-256 bit states that the instructions run in constant time
// (cpu_cfg.h).
void webpki_ticket_binding(uint32_t cpu, const uint8_t *psk, size_t psk_len,
                           const uint8_t config_hash[SHA256_LEN], uint8_t out[SHA256_LEN]);

// Whether cfg's PSK fields are one this build accepts. cfg is the
// session's copy, into which hspost_present_ticket wrote a presented
// ticket's PSK and identity. Either every PSK field is unset: psk and
// psk_id NULL, psk_len and psk_id_len 0, and ticket NULL. Or cfg presents
// a ticket: ticket set, a psk of SHA256_LEN bytes, or of SHA384_LEN bytes
// in a CH_CLIENT_AES_SUITES build (ch_ticket.psk_len), a psk_id of 1 to
// CH_TICKET_ID_MAX bytes, and the ticket's binding equal, compared in
// constant time, to the binding recomputed from psk, hostname and
// anchors. Any other shape is refused: an external PSK has no hostname
// to bind, and a length set without its pointer is a field missing. The
// hash and the binding it recomputes run on the path cfg's own cpu value
// names, as webpki_ticket_config_hash states.
//
// Requires: the hostname, anchor and SPKI pin rules already hold
// (webpki_cfg.c). In a host object, cfg->cpu holds
// CH_CPU_CONSTANT_TIME_SHA256 only on a CPU with the SHA-256
// instructions. tlsi_config_ok and quic_config_ok run cpu_value_ok on
// cfg->cpu before this call, so a value they refuse runs no hash.
int webpki_resumption_ok(const ch_cfg *cfg);

#endif // CH_TRUST_WEBPKI
#endif
