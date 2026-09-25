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
// Requires: cfg->hostname holds hostname_len bytes, cfg->anchors holds
// anchor_count entries whose pointers hold their lengths, and
// cfg->spki_pins holds spki_pin_count pins, which the webpki config
// rules check before any caller runs this.
void webpki_ticket_config_hash(const ch_cfg *cfg, uint8_t out[SHA256_LEN]);

// The binding a ticket carries: HMAC-SHA256 keyed by the ticket's PSK,
// the psk_len bytes at psk, over the label "chapulin webpki ticket" and
// the hash above. The binding stays SHA-256 whatever hash the PSK came
// from, because it is this client's own check and no protocol value.
void webpki_ticket_binding(const uint8_t *psk, size_t psk_len,
                           const uint8_t config_hash[SHA256_LEN], uint8_t out[SHA256_LEN]);

// Whether cfg's PSK fields are one this build accepts. Either every PSK
// field is unset: psk and psk_id NULL, psk_len and psk_id_len 0,
// resumption 0 and ticket_binding NULL. Or cfg presents a ticket:
// resumption set, a psk of SHA256_LEN bytes, or of SHA384_LEN bytes in a
// CH_CLIENT_AES_SUITES build (ch_ticket.psk_len), a psk_id of 1 to
// CH_TICKET_ID_MAX bytes, and a ticket_binding equal, compared in
// constant time, to the binding recomputed from psk, hostname and
// anchors. Any other shape is refused: an external PSK has no hostname
// to bind, and a length set without its pointer is a field missing.
//
// Requires: the hostname, anchor and SPKI pin rules already hold
// (webpki_cfg.c).
int webpki_resumption_ok(const ch_cfg *cfg);

#endif // CH_TRUST_WEBPKI
#endif
