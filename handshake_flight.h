// The client's flight handlers, one function per handshake message, over
// the handshake_state and the ch_tls it points at. Both transports
// compile this file: the TLS driver in handshake.c calls these in one
// straight line, and the QUIC driver in quic_step.c calls the same
// functions one per step, so no protocol rule exists twice
// (docs/quic.md, "The design: one whole message per step").
//
// None of these functions calls the record layer, the I/O shim or a
// tlsi_ function. Each reads its message through hsr_next_msg and writes
// its outgoing bytes into a caller buffer, so the transport alone
// decides how a message arrives and how it goes out.
//
// How a message arrives differs by transport, and every function that
// reads one inherits the difference. Under TRANSPORT=tls hsr_next_msg
// reads records from the caller's recv callback until the message is
// whole, so these functions block and can report CH_EIO and CH_EAUTH.
// Under CH_TRANSPORT_QUIC hsr_next_msg never waits, so the driver must
// have confirmed a whole message with hsr_peek_message before it calls
// one of these; a call made without that check returns CH_EINVAL and
// changes nothing. RFC 9001 §4.1.3 splits the buffering that way: TLS
// buffers the handshake bytes that arrived in order and QUIC buffers
// the rest (rfc9001.txt:501-504).
//
// Failure is uniform. A function that returns anything but CH_OK writes
// the alert description into h->alert first, and the driver sends that
// alert and kills the session. A function that returns CH_OK leaves
// h->alert holding whatever the last writer put there, so every
// function seeds it before it parses. No function here wipes the
// session; the driver does that on the way out.
#ifndef CH_HANDSHAKE_FLIGHT_H
#define CH_HANDSHAKE_FLIGHT_H

#include <stddef.h>
#include <stdint.h>

#include "handshake_parser.h"
#include "handshake_record.h"
#include "sha256.h"

// The client Finished message, header included: the 4-byte handshake
// header and one verify_data of SHA256_LEN bytes (RFC 9846 §4.5.3,
// rfc9846.txt:3141-3143). The length is fixed, so hsf_complete writes
// exactly this many bytes and needs no capacity argument.
#define HSF_FINISHED_LEN (4 + SHA256_LEN)

// Draws the ephemeral secrets and starts the transcript. Writes
// h->priv, h->pub and h->random, writes h->dz under KEX=pq, computes
// h->early and h->binder_key from cfg.psk when the caller configured
// one and from a hash-length zero string when it did not (RFC 9846
// §7.1, rfc9846.txt:4034), and calls sha256_init on t->transcript.
//
// Requires a handshake_state the caller has zeroed and whose t points
// at the session. Runs before any message goes out or comes in, once
// per session: a second call would draw a second key share and the
// retry ClientHello would no longer match the first.
//
// Returns nothing and cannot fail on peer input. It holds the
// integrator's ch_rand_bytes to rand.h's contract with CH_ASSERT: an
// all-zero draw is a hook that returned without writing, which is
// programmer error, not peer input. A real draw is all-zero with
// probability 2^-256.
void hsf_begin(handshake_state *h);

// Builds one ClientHello into out, header included, and adds it to the
// transcript. In PSK mode it computes the binder over the
// transcript-so-far plus the truncated hello and writes it into the
// message's last SHA256_LEN bytes (RFC 9846 §4.3.11.2,
// rfc9846.txt:2586). It echoes h->cookie when h->cookie_len is not 0,
// which is what makes this the retry hello (RFC 9846 §4.2.4,
// rfc9846.txt:1444).
//
// Requires hsf_begin to have run, and cap bytes at out. The caller
// passes the staging array its transport wants: a TLS driver passes
// t->tx + REC_HDR and leaves room for the record header it writes
// itself, and a QUIC driver passes t->tx whole, because RFC 9001 §4.1.3
// puts no record header in front of a CRYPTO frame's bytes
// (rfc9001.txt:462-464).
//
// Returns the message length in bytes. Returns 0 when cap is shorter
// than the hello, and then writes ALERT_INTERNAL_ERROR into h->alert
// and leaves the transcript untouched, so a short staging array is a
// build mistake the session dies on rather than a half-hashed message.
// The bytes at out are undefined after a 0 return.
size_t hsf_build_client_hello(handshake_state *h, uint8_t *out, size_t cap);

// Reads one ServerHello, or the HelloRetryRequest that shares its type
// (RFC 9846 §4.2.3, rfc9846.txt:1329; §4.2.4, rfc9846.txt:1444), parses
// it into info, and advances the transcript. On a HelloRetryRequest it
// replaces the transcript with the synthetic message_hash construction
// RFC 9846 §4.1 prescribes (rfc9846.txt:1076-1082) and copies the
// cookie into h->cookie and h->cookie_len, so the retry hello can echo
// it. On a ServerHello it hashes the raw message.
//
// Requires a whole message to be readable; see the transport note at
// the top. info need not be zeroed: this function zeroes it.
//
// Returns CH_OK, and then info->hrr says which message arrived. The
// caller decides what a HelloRetryRequest means, because the two
// transports refuse a second one differently: the TLS driver refuses it
// by call position and the QUIC driver refuses it by the stored step.
//
// Returns CH_EPROTO with ALERT_UNEXPECTED_MESSAGE for any other
// handshake type; CH_EPROTO with ALERT_ILLEGAL_PARAMETER when
// hsp_parse_server_hello refuses the message, and for a
// HelloRetryRequest that carries no cookie, which is an HRR that
// changes nothing this client offered and which RFC 9846 §4.2.4 makes
// an illegal_parameter abort (rfc9846.txt:1467-1469). It also returns
// what hsr_next_msg returns: CH_EIO, CH_EPROTO, CH_EAUTH or CH_ECAP
// under TRANSPORT=tls, and CH_EPROTO or CH_EINVAL under
// CH_TRANSPORT_QUIC. On every failure the transcript may already hold
// the message, which costs nothing because the session dies.
int hsf_read_server_hello(handshake_state *h, server_hello_info *info);

// Judges an accepted ServerHello: the one this client can continue
// from. Writes t->group from the group the parser read off the wire,
// whether or not the rest passes, because the session reports the group
// either way.
//
// Requires an info that hsf_read_server_hello filled and whose hrr is
// 0. Reads info and does not write it.
//
// Returns CH_OK when the message carried a key share this build
// accepts, and, in PSK mode, when the server also accepted the identity
// this client offered.
//
// Returns CH_EAUTH with ALERT_HANDSHAKE_FAILURE when the ServerHello
// carried no acceptable key share, or when cfg.psk is set and the
// server ignored the identity: either one leaves the client with no
// keys it can continue under, and a PSK server that ignores the
// identity would want certificates this build did not pin (RFC 9846
// §4.2.3, rfc9846.txt:1329).
//
// Under KEX=pq it also returns CH_EPROTO with ALERT_ILLEGAL_PARAMETER
// when cfg.require_pq is set and the group the parser wrote is not
// CH_GROUP_X25519MLKEM768. The compare reads the field the parser wrote
// rather than the constant the build offered.
int hsf_accept_server_hello(handshake_state *h, const server_hello_info *info);

// Completes the key exchange and derives the handshake secrets. Runs
// x25519 over h->priv and info->server_pub, or, under KEX=pq,
// decapsulates info->server_ct with the key pair h->dz re-expands and
// puts the ML-KEM shared secret ahead of the x25519 one, which is RFC
// 10024's order despite the group's name. Then it takes the transcript
// hash and calls ks_handshake, writing h->handshake_secret, h->c_hs and
// h->s_hs (RFC 9846 §7.1, rfc9846.txt:4034).
//
// Requires an info that hsf_accept_server_hello accepted, and, under
// KEX=pq, that info->server_ct still points at the live ServerHello
// bytes in cfg.buf: nothing may read a further message between the
// parse and this call.
//
// Wipes h->priv, h->pub, h->random, h->early, h->binder_key and, under
// KEX=pq, h->dz on both exits, along with the shared secret itself.
// After this call the retry hello can no longer be built, which is
// correct: the exchange is over. The wipes are in this function because
// the QUIC driver returns to its caller between messages, so the frame
// wipe the TLS driver ends the handshake with is a round trip away
// (docs/quic.md, "Entry points and their contracts").
//
// Returns CH_OK, or CH_EPROTO with ALERT_ILLEGAL_PARAMETER when x25519
// yields the all-zero shared secret, which RFC 9846 §7.4.2 makes a MUST
// (rfc9846.txt:4293-4295). Decapsulation itself cannot fail: a
// tampered ciphertext yields the implicit-reject secret and the
// handshake dies at the server Finished instead.
int hsf_derive_handshake_secrets(handshake_state *h, const server_hello_info *info);

// Reads the EncryptedExtensions and applies what it carries (RFC 9846
// §4.4.1, rfc9846.txt:2650). Seeds h->alert with ALERT_ILLEGAL_PARAMETER
// before it parses, because hsp_parse_encrypted_exts overrides that only
// where it knows a better alert, and the override must reach the wire.
// Lowers t->peer_limit to the peer's record_size_limit under
// TRANSPORT=tls, records the server's ALPN choice in t->alpn_selected
// where the build offers protocols, and adds the raw message to the
// transcript.
//
// Under CH_TRANSPORT_QUIC it does two more things. It hands the
// server's quic_transport_parameters body to cfg.on_transport_params
// when the caller set that callback, unread, because the body belongs
// to the QUIC version in use and is opaque to TLS (RFC 9001 §8.2,
// rfc9001.txt:1926-1928). It takes that body from
// hsp_parse_encrypted_exts, whose QUIC arm reports it through two out
// parameters (handshake_parser.h), and it calls the callback before it
// returns, while the pointer into cfg.buf is still valid. And it
// refuses a handshake that negotiated no
// application protocol: t->alpn_selected still CH_ALPN_NONE here is
// CH_EPROTO with ALERT_NO_APPLICATION_PROTOCOL, which RFC 9001 §8.1
// requires of a QUIC client (rfc9001.txt:1897-1902) and which is the
// one place this build differs from docs/webpki.md's rule, where a
// server that sends no ALPN extension leaves the selection empty and
// the handshake completes.
//
// Requires a whole message to be readable; see the transport note at
// the top. Requires the handshake keys to be installed, because on TLS
// this message arrives protected.
//
// Returns CH_OK. Returns CH_EPROTO with ALERT_UNEXPECTED_MESSAGE for
// any other handshake type, and CH_EPROTO with the alert the parser
// chose for a message it refuses: ALERT_ILLEGAL_PARAMETER by default,
// ALERT_UNSUPPORTED_EXTENSION for an extension this client never
// offered (RFC 9846 §4.3, rfc9846.txt:1504), and, under
// CH_TRANSPORT_QUIC, ALERT_MISSING_EXTENSION for a message that carries
// no quic_transport_parameters (RFC 9001 §8.2, rfc9001.txt:1929-1936).
// It also returns what hsr_next_msg returns, as hsf_read_server_hello
// does.
int hsf_read_encrypted_extensions(handshake_state *h);

// Reads the server Finished and verifies it. Takes the transcript hash
// before it reads the message, computes the expected verify_data from
// h->s_hs, and compares with ct_memeq (RFC 9846 §4.5.3,
// rfc9846.txt:3145-3150). On a match it adds the raw message to the
// transcript and sets h->server_finished_ok, the flag hsa_epoch_commit
// and hsf_complete require.
//
// Requires a whole message to be readable; see the transport note at
// the top. Requires h->s_hs, so it runs after
// hsf_derive_handshake_secrets.
//
// Returns CH_OK when the MAC compared equal.
//
// Returns CH_EAUTH with ALERT_DECRYPT_ERROR when it did not, which RFC
// 9846 §4.5.3 requires (rfc9846.txt:3115-3117). Returns CH_EAUTH with
// ALERT_HANDSHAKE_FAILURE for a Certificate or CertificateRequest where
// none belongs: a PSK server that rejected the PSK, or a pinned-key
// server asking for client authentication this build cannot do.
// Returns CH_EPROTO with ALERT_UNEXPECTED_MESSAGE for any other type,
// and for a Finished whose length is not HSF_FINISHED_LEN. It also
// returns what hsr_next_msg returns, as hsf_read_server_hello does.
int hsf_read_finished(handshake_state *h);

// Ends the handshake's key schedule and builds the client Finished.
// Takes the transcript hash, runs ks_master to write h->master,
// t->wr_secret and t->rd_secret, writes the Finished message into
// finished from h->c_hs, adds that message to the transcript, then
// takes the transcript hash again and runs ks_res_master into
// t->res_master (RFC 9846 §7.1, rfc9846.txt:4034).
//
// The order differs from the tree at 022711d in one step:
// ks_res_master runs here, before the Finished goes out, where the TLS
// driver ran it after the send. Nothing observable depends on it. A
// failed send wipes the session either way, and tlsi_wipe clears
// res_master, so the field a failed send leaves behind is zero as
// before. The change exists because the QUIC driver hands the Finished
// to its caller and learns nothing about the send.
//
// Requires h->server_finished_ok, which is programmer error to skip
// rather than peer input: running the client Finished before the server
// proved it holds the keys would answer an unauthenticated peer.
// CH_ASSERT holds it. Requires HSF_FINISHED_LEN bytes at finished.
//
// Returns nothing and cannot fail. The caller owns what happens next:
// the TLS driver seals the message into a record and sends it, and the
// QUIC driver stages it at the Handshake encryption level for
// ch_quic_crypto_out. Both then install the application traffic keys
// from t->wr_secret and t->rd_secret.
void hsf_complete(handshake_state *h, uint8_t finished[HSF_FINISHED_LEN]);

#endif
