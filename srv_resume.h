// Resumption on the server: which ticket a ClientHello resumes, and the
// NewSessionTicket a connection ends its handshake with. srv_ticket.[ch]
// is the format; this pair is the two flight steps that use it. Only a
// ROLE=server build compiles it. docs/server.md, "Resumption", states the
// role, and docs/decisions.md entry 51 the choices below.
//
// The server issues one ticket per connection, full or resumed, and
// accepts one of its own tickets as a PSK under psk_dhe_ke alone. It
// accepts no external PSK, sends no early_data extension anywhere, and
// reads no clock: the caller writes the instant into
// ch_cfg.srv.now_seconds before each connection, and 0 there means no
// clock, which issues no ticket and accepts none.
//
// What a ticket binds, and why each term:
//
//   - The PSK, because it is what the resumed handshake authenticates
//     with.
//   - The cipher suite, because RFC 9846 §4.7.1 lets a ticket resume only
//     under a suite with the same KDF hash (rfc9846.txt:3219-3220). Every
//     suite this build holds hashes with SHA-256, so a ticket resumes
//     under any of them.
//   - auth_seconds, the instant of the last full handshake behind the
//     ticket, so the lifetime is judged on the server's clock against a
//     value the client cannot alter, and a chain of resumptions cannot
//     outlive one lifetime (srv_ticket.h).
//   - The ALPN protocol, so a ticket resumes only a connection that
//     negotiates the protocol the ticket was issued under. RFC 9846 ties
//     the protocol to a ticket only for 0-RTT (rfc9846.txt:2419), which
//     this server refuses, so this is policy rather than obligation: RFC
//     9001 §4.5 lets application protocols keep state across resumed
//     connections (rfc9001.txt:752-754), and a ticket that crossed
//     protocols would carry one protocol's session into another. A
//     mismatch costs one full handshake.
//
// What it does not bind, and why. Not the server_name: RFC 9846 §4.3.11
// says a TLS 1.3 server need not associate one with a ticket
// (rfc9846.txt:2525-2527), and this server selects no identity by name.
// Not the signing identity: the PSK proves that the server holds the
// ticket key, which every identity of one deployment shares, and a
// deployment that retires an identity and wants its tickets gone rotates
// the ticket key. Not the ticket_age_add or the client's
// obfuscated_ticket_age: RFC 9846 uses the age for 0-RTT anti-replay
// (rfc9846.txt:4487-4499), and auth_seconds on the server's own clock is
// the stronger lifetime check for a server that refuses 0-RTT.
#ifndef CH_SRV_RESUME_H
#define CH_SRV_RESUME_H
#ifdef CH_ROLE_SERVER

#include <stddef.h>
#include <stdint.h>

#include "handshake_record.h"
#include "srv_message.h"
#include "srv_parser.h"
#include "srv_ticket.h"

// Chooses how this handshake authenticates the server: with a ticket the
// client offered, or else with the certificate identity sel->sigalg
// names. srv_select calls it once no retry is owed, and
// srv_check_retry_hello calls it for the second hello, whose binders
// cover the HelloRetryRequest.
//
// A ticket is considered when all four hold: cfg.srv.ticket_key is set;
// cfg.srv.now_seconds is not 0; the hello carried pre_shared_key; and its
// psk_key_exchange_modes listed psk_dhe_ke. RFC 9846 §4.3.9 forbids a
// server to select a mode the client did not list (rfc9846.txt:2307-2308),
// and psk_ke runs no key exchange, which this server never does, so a
// client that lists psk_ke alone gets a full handshake.
//
// The order rule. The identities are read in the client's order, and the
// first one that passes every test below is selected. Each identity is
// tested alone and only its own binder is checked, which RFC 9846
// §4.3.11 asks of a server (rfc9846.txt:2544-2546). An identity passes
// when it is SRV_TICKET_LEN bytes long, srv_ticket_open opens it under
// the ticket key, now_seconds is at least its auth_seconds and at most
// SRV_TICKET_LIFETIME seconds past it, its suite is one this build holds,
// and its ALPN protocol is the one the parser selected for this hello, or
// both are none. An identity that fails any test is passed over, which
// RFC 9846 §4.3.11 asks of an unknown PSK (rfc9846.txt:2533-2537), and no
// failure here ends the handshake.
//
// The binder. For the selected identity it derives the binder key from
// the ticket's PSK with ks_early's "res binder" label, computes the
// expected binder over ch->binder_hash with ks_verify_data, and compares
// it with the client's binder at the same index with ct_memeq over all
// SHA256_LEN bytes (RFC 9846 §4.3.11.2). A binder that is absent, not
// SHA256_LEN bytes long, or not equal ends the handshake with
// decrypt_error, which RFC 9846 §4.3.11 requires (rfc9846.txt:2541-2544)
// and §6.2 names (rfc9846.txt:3968-3970).
//
// Requires a ch that srv_read_client_hello filled, so binder_hash is the
// transcript hash over the hello truncated before its binders; and a sel
// whose suite, hash_len and sigalg are written. sigalg is 0 when no
// provisioned identity signs a scheme the client offered.
//
// Returns CH_OK with sel->psk_selected set, sel->psk_identity the selected
// index, h->early the early secret of the ticket's PSK and
// h->ticket_auth_seconds the ticket's auth_seconds. Returns CH_OK with
// sel->psk_selected clear when no ticket was selected and sel->sigalg is
// not 0: a full handshake follows.
//
// Returns CH_EAUTH with ALERT_DECRYPT_ERROR for the binder refusal above,
// having wiped h->early. Returns CH_EPROTO when no ticket was selected and
// sel->sigalg is 0: with ALERT_MISSING_EXTENSION when the hello carried no
// signature_algorithms, which RFC 9846 §4.3.3 requires of a server that
// authenticates with a certificate (rfc9846.txt:1812-1816), and with
// ALERT_HANDSHAKE_FAILURE when it carried one and no scheme overlaps
// (rfc9846.txt:1181-1184).
//
// It wipes every ticket body it opened and the binder key before it
// returns, on every path.
int srv_select_auth(handshake_state *h, const client_hello *ch, selection *sel);

// Issues one NewSessionTicket (RFC 9846 §4.7.1) under the application
// write key, after the client Finished verified, which §4.7.1 requires
// (rfc9846.txt:3194-3196). srv_handshake.c, srv_rec.c and srv_quic.c call
// it right after srv_complete, and a QUIC driver sets h->level to
// CH_LEVEL_APPLICATION first.
//
// It takes the transcript hash through the client Finished, runs
// ks_res_master over h->master and ks_res_psk over a fresh ticket_nonce,
// seals the PSK into a ticket with srv_ticket_seal, and sends the message
// srv_build_new_session_ticket writes. One ch_rand_bytes call draws the
// three random values: the ticket's AEAD nonce, ticket_age_add, which RFC
// 9846 §4.7.1 requires fresh per ticket (rfc9846.txt:3265-3270), and the
// SRV_TICKET_NONCE_LEN bytes of ticket_nonce. The message carries no
// extension, so it grants no early data.
//
// ticket_lifetime is what is left of SRV_TICKET_LIFETIME after the
// ticket's auth_seconds: all of it after a full handshake, and after a
// resumed one the lifetime less the seconds since the ticket it resumed
// was first issued.
//
// It sends nothing and returns CH_OK when cfg.srv.ticket_key is NULL, when
// cfg.srv.now_seconds is 0, or when a resumed chain has no lifetime left.
// A server with no clock issues no ticket, because it could never judge
// one.
//
// Requires srv_read_client_finished to have returned CH_OK, srv_complete to
// have run, and h->master and the transcript still live. It adds nothing to
// the transcript: a post-handshake message is not part of it.
//
// Returns CH_OK. Returns CH_EIO for a failed send, and CH_ECAP with
// ALERT_INTERNAL_ERROR when a builder refused, which is a build mistake
// rather than peer input. It wipes the resumption secret, the PSK and the
// ticket body before it returns, on every path.
int srv_send_new_session_ticket(handshake_state *h);

#endif // CH_ROLE_SERVER
#endif
