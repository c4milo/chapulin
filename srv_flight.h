// The server's flight handlers, one function per handshake message,
// over the handshake_state and the ch_tls it points at. It is the
// mirror of handshake_flight.[ch] on the other side of the connection.
// srv_handshake.c calls these in one straight line, so the order is the
// call order and there is no state variable to desynchronize. Only a
// ROLE=server build compiles it. docs/server.md states the role.
//
// Failure is uniform, and it is the same rule handshake_flight.h
// states. A function that returns anything but CH_OK writes the alert
// description into h->alert first, and the driver sends that alert and
// kills the session. A function that returns CH_OK leaves h->alert
// holding whatever the last writer put there, so every function seeds
// it before it parses. No function here wipes the session; the driver
// does that on the way out. proof/srv_flight_harness.c proves the
// first sentence over every handler.
//
// Two things in this file are not a mirror of the client's, and both
// are stated at the function that carries them. The two directions
// advance at different points, because the server must still read the
// client Finished under the handshake key. And the dummy
// change_cipher_spec follows whichever message the server wrote first,
// which gives srv_send_compat_ccs two call sites rather than one.
//
// The bound on an arriving ClientHello is the caller's buffer, stated
// rather than hidden: a message larger than cfg.buf_len minus REC_HDR
// dies with CH_ECAP and internal_error. A host caller that passes 64 kB
// accepts every legal ClientHello; a device caller that passes less
// accepts them up to its buffer. docs/server.md's open question eight
// records that a 512-byte device server does not accept every
// conformant ClientHello, and names the streaming reader that would
// close it.
#ifndef CH_SRV_FLIGHT_H
#define CH_SRV_FLIGHT_H
#ifdef CH_ROLE_SERVER

#include <stddef.h>
#include <stdint.h>

#include "handshake_parser.h"
#include "handshake_record.h"
#include "srv_auth.h"

// The hybrid key exchange has no server half here, for two structural
// reasons. handshake_state gives the server's share h->pub, which is
// X25519_LEN bytes against CH_KEX_SERVER_SHARE's 1120 under KEX=pq. And
// that share's ML-KEM half is a ciphertext under the client's
// encapsulation key, which srv_begin has not read where this header
// draws the server's secrets. Open question ten leaves the pair open.
// The guard sits in the header every server source includes, so a
// KEX=pq build stops at the first of them rather than at srv_flight.c
// alone.
#ifdef CH_KEX_PQ
#error "ROLE=server has no KEX=pq half yet (docs/server.md, open question ten); use KEX=x25519"
#endif

// The cookie fits the field the handshake state already carries, so the
// retry costs the session no new bytes. Both constants are visible
// here and nowhere lower, which is why the assertion sits in this
// header; handshake.c asserts CH_HELLO_MAX against CH_TX_STAGE the
// same way. The library builds as C, so the guard always runs.
#ifndef __cplusplus
_Static_assert(SRV_COOKIE_MAX <= HSP_COOKIE_MAX,
               "a minted cookie must fit the handshake state's cookie field");
#endif

// Draws the server's ephemeral secrets and starts the transcript.
// Writes h->priv and h->pub, writes h->dz under KEX=pq, and calls
// sha256_init on t->transcript. It does not draw the ServerHello random
// here: that value is drawn where the message is built, because a
// HelloRetryRequest carries srv_hrr_random in its place and the two
// messages are written at different call sites.
//
// Requires a handshake_state the caller has zeroed and whose t points
// at the session. Runs before any message goes out or comes in, once
// per session.
//
// Returns nothing and cannot fail on peer input. It holds the
// integrator's ch_rand_bytes to rand.h's contract with CH_ASSERT, as
// hsf_begin does: an all-zero draw is a hook that returned without
// writing, which is programmer error and not peer input.
// Whether this configuration can serve: every rule srv.h states, with the
// transport's own arm. srv.c holds the predicates and both drivers ask it,
// because a QUIC server needs the same answer ch_srv_accept needs and
// gets it through a different entry. Declared for that second caller
// alone, so a TLS build keeps it internal to srv.c.
#if defined(CH_TRANSPORT_QUIC) || defined(CH_TRANSPORT_RECORD)
int srv_config_ok(const ch_cfg *cfg);
#endif

void srv_begin(handshake_state *h);

// Reads one ClientHello, parses it into ch, and adds the raw message to
// the transcript. It copies the client's legacy_session_id into the
// session, because that value must survive a HelloRetryRequest round
// trip (rfc9846.txt:1451) and the buffer the message sits in does not.
// It copies the server_name into cfg.srv.sni_buf when the caller
// supplied one and the name fits; a longer name is not copied
// and t->sni_len stays 0, which is the same answer the caller sees for
// a ClientHello that carried no name.
//
// It is called at most twice per session, and the second call reads the
// retried ClientHello. Nothing in this function tells the two apart:
// the state machine does, by call position, and srv_check_retry_hello
// is what runs after the second.
//
// Requires srv_begin to have run, and, on the second call, a
// transcript srv_send_hello_retry_request has already replaced with
// §4.1's synthetic message_hash construction. ch need not be zeroed:
// this function zeroes it.
//
// Returns CH_OK with ch filled.
//
// Returns CH_EPROTO with ALERT_UNEXPECTED_MESSAGE for any other
// handshake type, and for a ClientHello that arrives after TLS 1.3 was
// negotiated, which RFC 9846 §4.2.2 requires (rfc9846.txt:1215-1217).
// Returns CH_EPROTO with the alert srv_parse_client_hello chose for a
// message it refuses. Returns CH_ECAP with ALERT_INTERNAL_ERROR for a
// ClientHello larger than the caller's buffer, because the RFC defines
// no alert for a local limit and §6.2 describes internal_error as an
// error unrelated to the correctness of the protocol
// (rfc9846.txt:3979-3981). It also returns what hsr_next_msg returns:
// CH_EIO, CH_EPROTO or CH_ECAP.
int srv_read_client_hello(handshake_state *h, client_hello *ch);

// Chooses what this connection will use, from the offer in ch and the
// configuration in the session: the cipher suite and the hash length it
// fixes, the group, the signature scheme and therefore the signing
// identity, and whether a HelloRetryRequest is owed. It writes sel
// whole and sends nothing.
//
// The preference order is a build constant and not configuration. The
// suite order is the one RFC 9846 §9.1 lists (rfc9846.txt:4540-4543)
// with ChaCha20-Poly1305 first; today it is the only suite this build
// holds, because the only AES in this tree is the software S-box table
// in quic_aes.c, which is admitted for QUIC Initial keys because those
// are public and which would leak a TLS traffic key through cache
// timing. So this build does not meet §9.1's cipher suite requirement
// and does not claim to. The group order and the signature scheme
// order are docs/server.md's, and a scheme whose identity slot
// srv_identity_live leaves unset is not selected.
//
// It sets sel->need_retry when both halves hold: the client's
// supported_groups names the group this build holds, and its key_share
// carried no KeyShareEntry for that group. RFC 9846 §4.2.1 makes that
// a MUST (rfc9846.txt:1158-1161) and §4.2.4 states the same condition
// in general terms (rfc9846.txt:1446-1449). Those two halves are
// exactly the two checks the client runs on selected_group in reply
// (rfc9846.txt:2205-2212), so a server that set the flag any other way
// would send a HelloRetryRequest the client aborts. The common input
// is the empty client_shares list §9.2 permits
// (rfc9846.txt:4599-4601), which is strictly conformant and costs one
// round trip.
//
// Requires a ch that srv_read_client_hello filled and a writable sel.
//
// Returns CH_OK with sel written.
//
// Returns CH_EPROTO with ALERT_HANDSHAKE_FAILURE when the offer and
// this build do not overlap in suites, in groups or in signature
// schemes, which RFC 9846 §4.2.1 requires when no acceptable set of
// parameters exists (rfc9846.txt:1145-1148, rfc9846.txt:1181-1184).
// Failing on a group named in supported_groups is not that case, and
// is the retry above.
//
// Returns CH_EPROTO with ALERT_NO_APPLICATION_PROTOCOL when all three
// of RFC 7301 §3.2's terms hold. §3.2 says a server that supports none
// of the protocols the client advertises "SHALL respond with a fatal
// no_application_protocol alert", and each term below is a term of that
// sentence:
//
//   1. The caller offers protocols, so cfg.alpn_count is not 0. A
//      caller that offers none negotiates no ALPN at all, which §3.2
//      permits: srv_send_encrypted_extensions then writes no ALPN
//      extension and the connection runs without one.
//   2. The client sent an application_layer_protocol_negotiation
//      extension, so SRV_EXT_ALPN is set in ch->seen. A client that
//      sent none asked for nothing and cannot fail to get it. The bit
//      is what tells those two hellos apart, because alpn_selected is
//      CH_ALPN_NONE for both (srv_parser.h).
//   3. No name is on both lists, so alpn_selected stayed CH_ALPN_NONE
//      after a list the parser read. That is the empty intersection
//      §3.2 names.
//
// The check runs before need_retry above, so a mismatch ends the
// handshake on the first ClientHello. A HelloRetryRequest would not
// change the answer: §4.2.2 forbids the second ClientHello to change
// the ALPN extension (rfc9846.txt:1191-1213), and ch->frozen covers it.
int srv_select(handshake_state *h, const client_hello *ch, selection *sel);

// Builds and sends one HelloRetryRequest, and replaces the transcript
// with §4.1's synthetic message_hash construction over the first
// ClientHello (rfc9846.txt:1084-1087). It mints the cookie with
// srv_cookie_mint from the first hello's transcript hash, the
// selection and ch->frozen, and copies it into h->cookie so the second
// hello's echo can be compared, and so the HelloRetryRequest's own
// bytes can be rebuilt on the way in.
//
// It is reached from exactly one call site, so a second
// HelloRetryRequest is unreachable by call position. No RFC sentence
// forbids a server from sending one — §4.2.4's limit is a client
// receipt obligation (rfc9846.txt:1469-1472) — but a server that sent
// one would fail every conformant client, and there is no third call
// site from which to send it.
//
// Requires a sel whose need_retry is set, and the first ClientHello
// already in the transcript.
//
// Returns CH_OK. Returns CH_EIO for a failed send, and CH_ECAP with
// ALERT_INTERNAL_ERROR when the session's staging array cannot hold
// the message, which is a build mistake rather than peer input.
int srv_send_hello_retry_request(handshake_state *h, const client_hello *ch, const selection *sel);

// Sends the dummy change_cipher_spec record, unsealed and outside the
// transcript, when the client's legacy_session_id was not empty. RFC
// 9846 Appendix E.4 has the server send it immediately after its first
// handshake message, which may be either a ServerHello or a
// HelloRetryRequest (rfc9846.txt:6391-6393), and Appendix E.4 makes it a MUST
// once the client sent a non-empty session id
// (rfc9846.txt:6401-6403). A client that sent an empty session id gets
// no record and this call sends nothing.
//
// It has two call sites, one after srv_send_hello_retry_request and
// one after srv_send_server_hello on the path with no retry, and the
// condition at each is the length of the client's session id and
// nothing else. A single call site after the ServerHello would put the
// record after the server's second handshake message on the retry
// path, and after the client had already sent its second ClientHello.
// Two call sites keep the flight a straight line with no flag.
//
// Requires a ch whose session_id_len says whether the record is owed.
//
// Returns CH_OK, including when it sent nothing. Returns CH_EIO for a
// failed send.
int srv_send_compat_ccs(handshake_state *h, const client_hello *ch);

// Checks the second ClientHello against the first and restarts the
// transcript from the cookie. It opens ch->cookie with
// srv_cookie_open, hashes the HelloRetryRequest bytes it rebuilds from
// the cookie's suite and group and the client's echoed session id,
// recomputes the frozen-fields digest over this hello and compares it
// with ct_memeq against the one the cookie carried, and confirms that
// the selection the cookie named still matches what this build holds.
// It writes sel from the cookie, so the two hellos cannot be answered
// under different parameters.
//
// It never sets sel->need_retry: the state machine has one retry by
// call position, and this is the only reader of a second hello.
//
// Requires a ch that srv_read_client_hello filled from the second
// ClientHello, and the selection the first hello produced.
//
// Returns CH_OK with sel written from the cookie.
//
// Returns CH_EPROTO with ALERT_ILLEGAL_PARAMETER when the cookie is
// absent, when srv_cookie_open refuses it, when the frozen digest does
// not compare equal, which is a client that changed a field RFC 9846
// §4.2.2 freezes (rfc9846.txt:1191-1213), and when the second hello
// carries an early_data extension, which §4.3.10 forbids there
// (rfc9846.txt:2397-2398). Returns CH_EPROTO with
// ALERT_HANDSHAKE_FAILURE when the second hello still carries no
// key_share for the group the cookie named.
int srv_check_retry_hello(handshake_state *h, const client_hello *ch, selection *sel);

// Builds and sends the ServerHello and adds it to the transcript. It
// draws the 32 random bytes here through ch_rand_bytes
// (rfc9846.txt:1358-1363), echoes the client's legacy_session_id
// (rfc9846.txt:1365-1368) and carries the server's key share for
// sel->group.
//
// Requires srv_begin to have run, so h->pub holds the share this
// message sends, and a sel whose need_retry is clear.
//
// Returns CH_OK. Returns CH_EIO for a failed send, and CH_ECAP with
// ALERT_INTERNAL_ERROR when the staging array cannot hold the message.
int srv_send_server_hello(handshake_state *h, const client_hello *ch, const selection *sel);

// Completes the key exchange and derives the handshake secrets, then
// installs the handshake keys in both directions. It runs x25519 over
// h->priv and the client's share, or, under KEX=pq, encapsulates to
// the client's encapsulation key and puts the ML-KEM shared secret
// ahead of the x25519 one, which is RFC 10024's order despite the
// group's name. Then it takes the transcript hash and calls
// ks_handshake (keysched.h), which writes the client secret before the
// server one.
//
// The two secrets bind to the opposite directions from the client's,
// and that is the whole of the asymmetry: this call passes h->c_hs to
// the read direction and h->s_hs to the write direction, where
// handshake.c:94-95 does the reverse. Nothing in INV-10 says which
// assignment is correct, so a server that swapped them would pass every
// check in the tree; docs/server.md lands a violation mutant for
// exactly that.
//
// Requires a ch whose share still points at live bytes in cfg.buf:
// nothing may read a further message between the parse and this call.
//
// Wipes h->priv and h->pub, and h->dz under KEX=pq, along with the
// shared secret itself, on both exits.
//
// Returns CH_OK. Returns CH_EPROTO with ALERT_ILLEGAL_PARAMETER when
// x25519 yields the all-zero shared secret, which RFC 9846 §7.4.2
// makes a MUST (rfc9846.txt:4293-4295); the client applies the same
// check to the server's share.
int srv_derive_handshake_secrets(handshake_state *h, const client_hello *ch, const selection *sel);

// Builds and sends the EncryptedExtensions, sealed under the handshake
// write key, and adds it to the transcript. It carries this server's
// own record_size_limit, sized to cfg.buf_len, and the ALPN protocol
// the parser selected, and it carries no early_data, which is what
// rejects 0-RTT (rfc9846.txt:2426-2428).
//
// From this message on, the server holds its own sends to the client's
// record_size_limit, the value ch->record_size_limit carried. Record
// size discipline runs in both directions: a record over the peer's
// limit is a protocol error and never a resize.
//
// Requires the handshake keys installed by srv_derive_handshake_secrets.
//
// Returns CH_OK. Returns CH_EIO for a failed send, and CH_ECAP with
// ALERT_INTERNAL_ERROR when the staging array cannot hold the message.
int srv_send_encrypted_extensions(handshake_state *h, const selection *sel);

// Sends the Certificate message for the selected identity and adds it
// to the transcript. The chain is the caller's size and not the
// build's, so this call never stages it whole: it writes the message
// header and the certificate_list framing with srv_message.h's
// builders, walks the identity's chain, and emits the message in
// fragments each sized to the smaller of CH_TX_PT and the peer's
// record limit, feeding the transcript hash as it goes and sealing
// each fragment as its own record. RFC 9846 §5.1 permits that
// fragmentation and forbids interleaving another record type
// (rfc9846.txt:3460-3462), which a straight-line writer cannot do.
//
// So the Certificate costs the session nothing whatever the chain's
// size, and the certificate bytes are never copied into ch_tls. The
// rejected alternative was a scatter-gather rec_seal that sealed the
// caller's chain pointer without copying; it is a second sealing entry
// point, which is what INV-1 exists to prevent.
//
// Requires a sel whose psk_selected is clear, because a PSK handshake
// sends no Certificate, and an identity srv_identity_for accepts.
//
// Returns CH_OK. Returns CH_EIO for a failed send, and CH_EINVAL with
// ALERT_INTERNAL_ERROR when the selected identity is not provisioned,
// which ch_srv_check should have caught at boot.
int srv_send_certificate(handshake_state *h, const selection *sel);

// Signs and sends the CertificateVerify, and adds it to the
// transcript. It takes the transcript hash as it stands after the
// Certificate, hands it to srv_sign_certificate_verify, and writes the
// message with the scheme and the signature that call produced.
//
// Requires a sel whose psk_selected is clear, and the Certificate
// already in the transcript: this call hashes the content the
// signature covers from the transcript as it stands, so anything
// hashed out of order would produce a signature no client verifies.
//
// Returns CH_OK. Returns CH_EIO for a failed send, and CH_EINVAL or
// CH_ECAP with ALERT_INTERNAL_ERROR when the signer refused, which
// srv_sign_certificate_verify's contract states.
int srv_send_certificate_verify(handshake_state *h, const selection *sel);

// Builds and sends the server Finished, adds it to the transcript,
// then runs ks_master and installs the application write key.
//
// This is the first of the two points where a direction advances, and
// the server cannot advance both here: it must still read the client
// Finished under the handshake key. srv_complete installs the
// application read key afterwards. A server that advanced both in one
// place would fail every handshake, and the two calls make the
// difference visible where a flag would hide it.
//
// Requires the handshake keys installed and the flight above already
// in the transcript.
//
// Returns CH_OK. Returns CH_EIO for a failed send.
int srv_send_finished(handshake_state *h);

// Reads the client Finished under the handshake read key and verifies
// it. It takes the transcript hash before it reads the message,
// computes the expected verify_data from h->c_hs, and compares with
// ct_memeq (RFC 9846 §4.5.3). On a match it adds the raw message to
// the transcript.
//
// Requires srv_send_finished to have run, so the transcript holds the
// server's own Finished, which the client's covers.
//
// Returns CH_OK when the MAC compared equal.
//
// Returns CH_EAUTH with ALERT_DECRYPT_ERROR when it did not, which RFC
// 9846 §4.5.3 requires (rfc9846.txt:3115-3117). Returns CH_EPROTO with
// ALERT_UNEXPECTED_MESSAGE for any other handshake type, for a
// Finished whose length is not the selected hash length, and for a
// KeyUpdate arriving before this message, which §4.7.3 forbids
// (rfc9846.txt:3346-3349). It also returns what hsr_next_msg returns.
int srv_read_client_finished(handshake_state *h);

// Installs the application read key and marks the session connected.
// It is the second of the two points where a direction advances, and
// it runs only after the client Finished verified, so no application
// byte is read under a key the peer has not proved it holds.
//
// The server also sends no application data before this point. RFC
// 9846 §4.5.3 permits it and says the server then has no assurance of
// the peer's identity or liveness (rfc9846.txt:3127-3130); refusing
// the permission costs nothing and removes a state, and ch_write
// before ch_srv_accept returns is not reachable through this API.
//
// Requires a srv_read_client_finished that returned CH_OK.
//
// Returns nothing and cannot fail.
void srv_complete(handshake_state *h);

#endif // CH_ROLE_SERVER
#endif
