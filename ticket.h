// The resumption ticket a client receives and presents again: what
// cfg.on_ticket hands over (RFC 9846 §4.6.1), the obfuscated age a
// resuming ClientHello carries (§4.3.11.1), and how long a client keeps
// one. cfg.h includes this header, because ch_cfg.on_ticket takes a
// ch_ticket, and it states the ch_cfg fields a resuming client sets:
// psk, psk_id, resumption, obfuscated_age, ticket_age_ms,
// ticket_lifetime_s, ticket_epoch and, over QUIC, ticket_quic_version.
#ifndef CH_TICKET_H
#define CH_TICKET_H

#include <stddef.h>
#include <stdint.h>

#include "hkdf.h"
#include "sha256.h"

// Ticket identities beyond this cannot fit a future ClientHello; larger tickets are dropped,
// and every client entry refuses a psk_id_len above it (cfg.h).
#define CH_TICKET_ID_MAX 320

// The longest a ticket is kept, in seconds. RFC 9846 §4.6.1 forbids a
// server a ticket_lifetime above 604800 seconds, 7 days, and forbids a
// client to use a ticket longer than 7 days after issuance whatever its
// ticket_lifetime says (rfc9846.txt:3255-3261). ch_cfg.ticket_age_ms is
// held to it in every build.
#define CH_TICKET_LIFETIME_MAX 604800U

// A resumption ticket for on_ticket. Copy what you keep during the callback, and present
// psk, psk_len and identity on the next connection with resumption = 1 for a cheaper
// reconnect. A ticket whose lifetime_s is 0 is never handed to on_ticket: RFC 9846 §4.6.1 says
// such a ticket is to be discarded at once (rfc9846.txt:3258-3259), so every ticket handed
// over has a lifetime of 1 second or more.
typedef struct {
    // Valid only during the callback: it points into the message, which the next record
    // overwrites.
    const uint8_t *identity;
    size_t identity_len;
    // The PSK is as long as the hash of the suite the session ran (RFC 9846 §4.6.1):
    // SHA256_LEN, or SHA384_LEN after a TLS_AES_256_GCM_SHA384 session, which only a
    // SUITE=aesgcm TRUST=webpki client runs. psk_len says which; present it as
    // ch_cfg.psk_len.
    uint8_t psk[HKDF_HASH_MAX];
    size_t psk_len;
    // ticket_lifetime in seconds, as the server sent it; present it as
    // ch_cfg.ticket_lifetime_s.
    uint32_t lifetime_s;
    // ticket_age_add, which ch_ticket_obfuscated_age adds to the ticket's age.
    uint32_t age_add;
    // The stored epoch when the ticket arrived; zero outside CA builds. Present it back in
    // ch_cfg.ticket_epoch on resumption, so an epoch bump also retires every earlier ticket.
    uint32_t epoch;
#ifdef CH_TRUST_WEBPKI
    uint8_t binding[SHA256_LEN]; // present it in ch_cfg.ticket_binding (webpki_ticket.h)
#endif
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
    // The negotiated QUIC version of the connection the ticket arrived on, which RFC 9369
    // section 5 makes the ticket's (rfc9369.txt:268-284). Present it in
    // ch_cfg.ticket_quic_version, and start the resuming connection in it: ch_quic_init refuses
    // a ticket whose version is not ch_cfg.quic_original_version.
    uint32_t quic_version;
#endif
} ch_ticket;

// A ROLE=server object compiles no client, so it declares no client call,
// as tls.h declares no ch_connect there.
#if !defined(CH_ROLE_SERVER) || defined(CH_ROLE_BOTH)
// The obfuscated_ticket_age a resuming ClientHello carries: the ticket's
// age in milliseconds plus the ticket's ticket_age_add, modulo 2^32 (RFC
// 9846 §4.3.11.1, rfc9846.txt:2574-2578). Put the answer in
// ch_cfg.obfuscated_age.
//
// age_ms is the time since on_ticket handed the ticket over, the value
// ch_cfg.ticket_age_ms takes. It is 64 bits wide, like that field, so a
// caller passes one value to both: the field keeps an age past 2^32
// milliseconds, about 49.7 days, stale, and this call reduces the sum
// modulo 2^32 itself.
//
// It reads ticket->age_add and no other field. A ch_ticket the caller
// copied during on_ticket and kept serves, although its identity pointer
// no longer points at the identity.
//
// Every client object exports it, over every transport, so its symbol name
// carries the object's transport, as ch_srv_check's does (srv.h): an image
// that links a tcp-nonblocking object and a QUIC object holds one of each
// (docs/decisions.md 61 and 72).
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#define ch_ticket_obfuscated_age ch_ticket_obfuscated_age_quic_nonblocking
#elif defined(CH_TRANSPORT_TCP_NONBLOCKING)
#define ch_ticket_obfuscated_age ch_ticket_obfuscated_age_tcp_nonblocking
#else
#define ch_ticket_obfuscated_age ch_ticket_obfuscated_age_tcp_blocking
#endif
uint32_t ch_ticket_obfuscated_age(const ch_ticket *ticket, uint64_t age_ms);
#endif

#endif
