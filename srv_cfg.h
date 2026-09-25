// What a ROLE=server build adds to the caller's configuration: the
// certificate chains and private keys this endpoint proves itself with,
// the key its HelloRetryRequest cookie is minted under, the key and the
// clock its resumption tickets need, and where to put the server_name a
// client sent. cfg.h includes this header and
// ch_cfg carries one ch_srv_cfg member, so a ROLE=client build declares
// none of it and keeps the ch_cfg layout it had.
//
// It sits beside cfg.h rather than inside it for one measured reason:
// cfg.h is 498 lines against the 500-line cap CLAUDE.md sets and
// make lint-size holds, so every declaration below would have broken
// that gate. docs/server.md sketches these fields flat inside ch_cfg;
// they are one member deep instead, and a caller writes
// cfg.srv.cookie_key where that sketch writes cfg.cookie_key.
//
// Nothing here answers "do I trust this peer". A server that requests
// no client certificate never asks, so ch_cfg's pin fields, its PSK
// offer fields and its epoch callbacks are the client's alone, and
// ch_srv_accept returns CH_EINVAL for a configuration that sets one.
//
// Every pointer here is the caller's and must outlive the session.
// chapulin copies none of them: a private key stays a pointer and is
// never copied into ch_tls, because a second copy of a
// deployment-lifetime secret in SRAM buys nothing when the original
// outlives every wipe.
#ifndef CH_SRV_CFG_H
#define CH_SRV_CFG_H

// The two build combinations a server has no meaning in. They stop here
// as well as in the Makefile's ROLE axis, so a firmware tree compiling
// these sources with its own build system meets the same refusal.
//
// A trust mode says how this endpoint judges a peer's key, of which a
// server that requests no client certificate has none, so CH_TRUST_CA
// and CH_TRUST_WEBPKI would compile a certificate parser no session
// reaches.
//
// A QUIC server builds, and docs/server.md's open question ten, which
// asked whether it was in scope, is answered. RFC 9001 §4.1.3 removes the
// record layer (rfc9001.txt:462-464), and the dummy change_cipher_spec,
// record_size_limit and the early-data discard disappear with it, which
// srv_flight.c's QUIC arms state.
#if defined(CH_ROLE_SERVER) && !defined(CH_ROLE_BOTH)
#if defined(CH_TRUST_CA) || defined(CH_TRUST_WEBPKI)
#error "a server-only object has no trust mode: drop CH_TRUST_*, or build ROLE=both"
#endif
#endif
// A QUIC server compiles this header, srv_flight.c's QUIC arm and
// srv_quic.c's driver (docs/quic_server.md).

#ifdef CH_ROLE_SERVER

#include <stddef.h>
#include <stdint.h>

// One certificate, as the DER bytes the caller holds in flash. chapulin
// writes them out unread: a ROLE=server object links no X.509 reader at
// all, so nothing here is parsed, and a malformed certificate is the
// client's to report (docs/server.md, "What the mode does not check,
// and why that is safe").
typedef struct {
    const uint8_t *der;
    size_t len;
} ch_cert;

// One signing identity: a certificate chain and the key pair that
// proves it. A server provisions one per signature scheme it offers,
// and RFC 9846 §9.1 names two for CertificateVerify —
// ecdsa_secp256r1_sha256 and rsa_pss_rsae_sha256
// (rfc9846.txt:4545-4547) — so a deployment that provisions one makes
// this server decline the other, and a client that offers only the
// declined scheme gets handshake_failure.
//
// The chain lists the end-entity certificate first (RFC 9846 §4.5.1,
// rfc9846.txt:2850-2851) and is never empty (rfc9846.txt:2876). A slot
// whose chain_count is 0 is not provisioned, the server never selects
// the scheme it signs, and ch_srv_check refuses a configuration with no
// identity at all.
//
// priv points at the private key and pub at the matching public key.
// Each signing module states the type it reads, and priv is void
// because the two types differ; priv_len is sizeof that type, which is
// what srv_auth.c tests before it hands the pointer on.
//
// ecdsa_p256: priv points at 32 big-endian bytes, the private scalar
// p256_sign.h calls P256_PRIV_LEN, and pub at the 64-byte uncompressed
// point X||Y that p256_ecdsa_verify reads (p256.h). So priv_len is 32
// and pub_len is 64.
//
// rsa_pss: priv points at one ch_rsa_priv (rsa_sign.h), which holds the
// modulus, the private exponent and their length, so priv_len is
// sizeof(ch_rsa_priv). pub points at the modulus alone, big-endian, and
// pub_len is its length, the n_len rsa_pss_verify admits: 256 to
// CH_RSA_MODULUS_MAX and a multiple of 8. An RSA-PSS signature is
// exactly pub_len bytes, which is the length srv_sign_certificate_verify
// tests the caller's buffer against.
//
// Three calls read the bytes behind these pointers and no other line
// does: p256_sign and rsa_pss_sign read priv, and ch_srv_check's
// boot-time self-test reads pub through the matching verifier.
// srv_auth.c reads the two lengths and passes the pointers on.
typedef struct {
    const ch_cert *chain;
    uint8_t chain_count;
    const void *priv;
    size_t priv_len;
    const uint8_t *pub;
    size_t pub_len;
} ch_identity;

// The server's own configuration, which ch_cfg carries as one member.
typedef struct {
    // The two signing identities this server may offer, one per
    // signature scheme. The scheme the client and this build agree on
    // picks which one signs the CertificateVerify.
    ch_identity ecdsa_p256; // signs ecdsa_secp256r1_sha256
    ch_identity rsa_pss;    // signs rsa_pss_rsae_sha256

    // The HMAC-SHA-256 key that protects the HelloRetryRequest cookie
    // (RFC 9846 §4.3.2, rfc9846.txt:1779-1783): 32 bytes, the
    // SRV_COOKIE_KEY_LEN srv_cookie.h states. One key per deployment,
    // so a second ClientHello that lands on a different session, or on
    // a different device behind a load balancer, still verifies.
    // ch_srv_accept returns CH_EINVAL when it is NULL, because RFC 9846
    // §9.2 makes the cookie extension mandatory to implement and a
    // stateless retry cannot be minted without it.
    const uint8_t *cookie_key;

    // Where to put the server_name a ClientHello carried (RFC 6066 §3),
    // and how many bytes fit. The handshake continues whether or not a
    // name arrived, and the server binds nothing to it: it holds no
    // certificate index and selects no identity by name. A name longer
    // than sni_cap is not copied, and the caller sees the result it
    // sees for a hello that carried none. Leave sni_buf NULL and
    // sni_cap 0 to drop every name; ch_tls.sni_len reports how many
    // bytes arrived.
    uint8_t *sni_buf;
    size_t sni_cap;

    // Refuse a ClientHello that carried no server_name, which RFC 9846
    // §9.2 permits a server to do (rfc9846.txt:4609-4612). It needs
    // sni_buf, because a server that required a name it cannot report
    // would refuse clients silently, and ch_srv_accept returns
    // CH_EINVAL for that pair.
    uint8_t require_server_name;

    // The ChaCha20-Poly1305 key this server seals its resumption
    // tickets under and opens them with: SRV_TICKET_KEY_LEN bytes
    // (srv_ticket.h), a key of its own and not cookie_key. One key per
    // deployment, so a ticket one server issued resumes on another that
    // holds the same key. NULL issues no ticket and accepts none, and
    // every handshake then authenticates with a certificate.
    //
    // It is as valuable as the private keys above: whoever holds it can
    // resume as this server with any client that kept a ticket, until
    // the tickets expire. srv_ticket.h states that, and when the key must
    // rotate.
    const uint8_t *ticket_key;

    // The caller's clock at the start of this connection, in seconds,
    // from the same epoch on every server that shares ticket_key; Unix
    // time is the plain choice. chapulin reads no clock of its own: it
    // writes this instant into every ticket it issues and judges every
    // ticket it is offered against it, so the caller writes it before
    // each ch_srv_accept, ch_srv_record_init or ch_srv_quic_init. 0 means
    // no clock, and a server with no clock issues no ticket and accepts
    // none, because it could not tell a fresh ticket from an expired one.
    uint64_t now_seconds;

#ifdef CH_SUITE_AES_GCM
    // The cipher suites this server selects from, in its order of
    // preference: cipher_suite_count code points, each one of the three
    // a -DCH_SUITE_AES_GCM build holds (suite.h). The server selects the
    // first of them the ClientHello lists and ignores the client's own
    // order. NULL with a count of 0 takes the default order,
    // TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256,
    // TLS_AES_256_GCM_SHA384, for the reasons srv_select states. A host
    // whose AES instructions outrun its ChaCha20 may put AES-GCM first,
    // and a list can leave a suite out. Any other shape, a code point
    // this build does not hold or a count without its list, makes
    // ch_srv_accept return CH_EINVAL (docs/decisions.md 58).
    const uint16_t *cipher_suites;
    size_t cipher_suite_count;
#endif

#ifdef CH_TRANSPORT_QUIC
    // Takes the server's handshake bytes as they are produced: level is a
    // CH_LEVEL_ value and the n bytes at p are CRYPTO frame content for it
    // (RFC 9001 section 4.1.3, rfc9001.txt:462-464). Returns 0 to accept
    // them and any other value to fail the handshake.
    //
    // A push, where the client's ch_quic_crypto_out is a pull, and the
    // certificate chain is what forces the difference: one Certificate
    // message is larger than ch_tls.tx, so there is no staging buffer to
    // pull from. One message can arrive as several calls and one call
    // never spans two messages. Both levels fire inside one
    // ch_quic_crypto_in, because one ClientHello produces the ServerHello
    // at CH_LEVEL_INITIAL and the rest of the flight at
    // CH_LEVEL_HANDSHAKE, so a caller needs a buffer per level rather than
    // one shared. docs/quic_server.md item 4 states the whole decision.
    // With ticket_key and now_seconds set, the call that delivers the
    // client Finished also produces one NewSessionTicket at
    // CH_LEVEL_APPLICATION, which the caller sends in 1-RTT CRYPTO frames
    // (RFC 9001 section 4.5).
    //
    // Required for a QUIC server: a server whose flight reaches nobody
    // completes no handshake. Re-entrancy: cfg.h's rule for
    // on_level_ready, for the same reason.
    int (*on_crypto_out)(void *io, uint8_t level, const uint8_t *p, size_t n);
#endif

#ifdef CH_TRANSPORT_RECORD
    // Takes the server's handshake records as they are produced: the n
    // bytes at p are one whole TLS record, header and all, ready for the
    // caller to write to its socket. Returns 0 to accept them and any
    // other value to fail the handshake.
    //
    // A push, where the client's ch_record_out is a pull, and the same
    // certificate chain forces the difference here that forces it over
    // QUIC. srv_flight.c stages a protected message on the handler's own
    // frame and streams the Certificate straight from cfg.srv.identity,
    // so there is no buffer for a caller to collect from and no point in
    // the flight where a stack frame may be abandoned. A pull would need
    // a resume point inside srv_out_sealed's record loop, which is the
    // one thing rec_step.h's "nothing inside it waits" rules out.
    //
    // Several calls arrive inside one ch_srv_record_in, because one
    // ClientHello produces the whole flight; the caller writes them in
    // the order they come. Each call carries one record, so a caller that
    // writes them separately still sends a legal stream. With ticket_key
    // and now_seconds set, the call that delivers the client Finished
    // also produces one NewSessionTicket record, sealed under the
    // application write key.
    //
    // The sink takes one whole record or fails the handshake, and cannot
    // report a short write. A caller whose socket accepts part of a
    // record buffers the remainder itself: reporting the short write back
    // would need the resume point the paragraph above rules out
    // (https://github.com/c4milo/chapulin/issues/170).
    //
    // Required for a record-mode server: a server whose flight reaches
    // nobody completes no handshake. Re-entrancy: cfg.h's rule for
    // on_level_ready, for the same reason.
    int (*on_record_out)(void *io, const uint8_t *p, size_t n);
#endif
} ch_srv_cfg;

#endif // CH_ROLE_SERVER
#endif
