// Parsers for the handshake messages that carry attacker-chosen bytes
// before the peer is authenticated: ServerHello (including
// HelloRetryRequest), EncryptedExtensions, Certificate framing and
// CertificateVerify. Pure functions over caller buffers — no I/O, no
// session state; handshake.c decides what the results mean.
// handshake_parser_ee.c defines hsp_parse_encrypted_exts and
// handshake_parser.c the other three. External linkage so proof, fuzz,
// and strictness-test builds reach the parsers without the state
// machine; the packaged library object localizes them like every other
// internal symbol.
#ifndef CH_HANDSHAKE_PARSER_H
#define CH_HANDSHAKE_PARSER_H

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "x25519.h"

// Longest HelloRetryRequest cookie we echo; anything larger is a
// protocol error.
#define HSP_COOKIE_MAX 128

// The ServerHello.random value that marks a HelloRetryRequest
// (RFC 9846 §4.2.3).
extern const uint8_t hsp_hrr_magic[32];

// Everything hsp_parse_server_hello learns from one ServerHello.
typedef struct {
    int hrr;
    int version_ok;
    int have_share;
    int psk_ok;
    uint8_t seen; // extension types already parsed, bits per parse_server_hello_ext
    // The NamedGroup the accepted key_share named; parse_key_share
    // writes it beside have_share, and it is 0 until then. The parser
    // accepts the build's one group and no other, so this is
    // CH_KEX_GROUP whenever have_share is set, read from the wire
    // rather than from that constant. A CH_KEX_TWO_GROUPS build also
    // accepts CH_GROUP_X25519 with a 32-byte share, and
    // hsf_read_server_hello decides which of the two the ServerHello
    // may select: the group the hello it answers carried a share for.
    uint16_t group;
#ifdef CH_KEX_TWO_GROUPS
    // The NamedGroup a HelloRetryRequest's key_share names, or 0 when
    // the retry carries none. The parser accepts CH_GROUP_X25519 alone
    // there: it is the one group the first hello offered without a
    // share (RFC 9846 §4.3.8, rfc9846.txt:2205-2211).
    uint16_t retry_group;
#endif
    uint8_t server_pub[X25519_LEN];
#ifdef CH_KEX_PQ
    // The ML-KEM ciphertext, MLKEM_CT_LEN bytes into the caller's
    // message — like cookie, the pointer dies at the next record read;
    // the handshake decapsulates before one runs.
    const uint8_t *server_ct;
#endif
    const uint8_t *cookie; // into the caller's message; NULL if absent
    size_t cookie_len;
#ifdef CH_SUITE_AES_GCM
    // The cipher_suite the message carried, which the parser accepts
    // only when this client offered it: TLS_CHACHA20_POLY1305_SHA256,
    // or TLS_AES_128_GCM_SHA256 from a CH_CLIENT_TWO_SUITES build. A
    // build with one suite has no field: the parser accepts one value.
    uint16_t suite;
#endif
} server_hello_info;

// Parses a ServerHello body (handshake header stripped) into info, which
// the caller zeroes first. psk_mode says whether the ClientHello offered
// a PSK. Returns CH_OK or CH_EPROTO; on CH_OK check info->hrr before
// trusting the share.
int hsp_parse_server_hello(const uint8_t *body, size_t n, server_hello_info *info, int psk_mode);

// Parses an EncryptedExtensions body. Lowers *peer_limit to the peer's
// record_size_limit when one arrives. Callers seed *alert with their
// default; the parser overwrites it only when it knows better (an
// extension we never offered gets unsupported_extension, RFC 9846
// §4.3). Returns CH_OK or CH_EPROTO.
//
// A TRUST=webpki build and a TRANSPORT=quic build take three more
// parameters, the ALPN arm (RFC 7301 §3.2). Both take them for the same
// reason and by the same guard cfg.h puts on ch_cfg.alpn_protocols: a
// webpki build offers a protocol list over TCP, and RFC 9001 §8.1
// requires ALPN of every QUIC client (rfc9001.txt:1891-1895). offered
// and offered_count are the protocol names the ClientHello listed,
// ch_cfg.alpn_protocols and ch_cfg.alpn_count. The caller seeds
// *selected with CH_ALPN_NONE, and the parser writes the index of the
// one name an ALPN extension carried. An offer of nothing
// (offered_count 0) makes an ALPN extension an unrequested response:
// unsupported_extension, like early_data. With an offer, the parser
// writes decode_error for a body that does not hold exactly one
// ProtocolName of 1 to 255 bytes, and, for a name the client did not
// offer, illegal_parameter under TRANSPORT=tls and
// no_application_protocol under CH_TRANSPORT_QUIC: RFC 9001 §8.1 makes
// a QUIC client terminate with error 0x0178 whenever ALPN negotiation
// fails (rfc9001.txt:1896-1902), which §4.8's 0x0100 conversion reaches
// from alert 120 and not from alert 47. A message with no ALPN
// extension is accepted and leaves *selected alone: RFC 7301 §3.2 lets
// a server that does not support ALPN send none. Under
// CH_TRANSPORT_QUIC that is still accepted here, and
// hsf_read_encrypted_extensions refuses the handshake that reached its
// end with *selected at CH_ALPN_NONE.
//
// A TRUST=webpki build takes three more parameters, after the ALPN
// ones, for the two extensions only its ClientHello may ask for.
//
// server_name_sent says whether the ClientHello carried server_name,
// which it does when ch_cfg.hostname_len is not 0. The parser then
// admits one server_name with empty extension_data, the acknowledgement
// RFC 6066 §3 allows, and writes decode_error (RFC 9846 §6) for one
// that carries data, which has the wrong length. With server_name_sent
// 0 any server_name is an unrequested response: unsupported_extension
// (RFC 9846 §4.3), as in the raw and ca builds, which send none.
//
// cert_types_offered is the server_certificate_type offer the
// ClientHello made, webpki_cert_types_offered's bit set of
// (1 << CH_CERT_TYPE_*), 0 when it sent no such extension. The caller
// seeds *cert_type with CH_CERT_TYPE_X509, and the parser writes the one
// CertificateType a server_certificate_type extension carried (RFC 7250
// §4.2, rfc7250.txt:474-487). An offer of 0 makes that extension an
// unrequested response: unsupported_extension (rfc9846.txt:3990-3993).
// With an offer, the parser writes decode_error for a body that is not
// exactly one byte (RFC 7250 §3, rfc7250.txt:317-324; RFC 9846 §6,
// rfc9846.txt:3784-3788) and illegal_parameter for a type the offer does
// not hold, any value of 8 or more included (rfc9846.txt:3789-3791): a
// server with no type in common sends unsupported_certificate instead
// (rfc7250.txt:435-438). A second one is refused like any repeated
// extension, with the caller's seed kept. A message with no such
// extension is accepted and leaves *cert_type alone: the server then
// sends X.509 certificates (RFC 9846 §4.5.1, rfc9846.txt:2846-2850),
// the type the seed names. The boundary is one byte of body, and the
// test rows are an offered type accepted, the other type refused with
// 47, and bodies of 0 and 2 bytes refused with 50.
//
// A TRANSPORT=quic build takes two more parameters and admits one more
// extension type, quic_transport_parameters at code point 0x39 (RFC
// 9001 §8.2, rfc9001.txt:1921-1923). On CH_OK *transport_params points
// into body at that extension's body and *transport_params_len is that
// body's length in bytes; the pointer dies at the next call that writes
// cfg.buf, so the caller copies what it keeps. The parser reads none of
// those bytes: their content belongs to the QUIC version in use and is
// opaque to TLS (rfc9001.txt:1926-1928).
//
// Absence is a refusal there, not a CH_OK. §8.2 makes a client that
// receives an EncryptedExtensions without the extension close with an
// error of type 0x016d (rfc9001.txt:1930-1936), so under
// CH_TRANSPORT_QUIC the parser reads its own seen mask before it
// returns: a message with the quic_transport_parameters bit clear
// writes missing_extension and returns CH_EPROTO, where the TLS arm
// ends its loop with the mask unread. The boundary test is one
// EncryptedExtensions carrying the extension accepted and the same
// message with it removed refused with alert 109.
//
// The 0x39 arm sits under CH_TRANSPORT_QUIC alone, never under the
// guard the ALPN block takes, so a TRANSPORT=tls build reaches the
// unadmitted arm and answers unsupported_extension. RFC 9001 §8.2
// requires exactly that of an implementation that understands the
// extension on a transport that is not QUIC (rfc9001.txt:1945-1949).
//
// peer_limit keeps its parameter and its meaning on both transports.
// Under CH_TRANSPORT_QUIC the caller passes a local it drops, because
// that build declares no ch_tls.peer_limit: RFC 9001 §4.1.3 removes the
// record layer record_size_limit sizes (rfc9001.txt:462-464), and
// cfg.buf_len bounds one level's reassembled CRYPTO bytes instead.
int hsp_parse_encrypted_exts(const uint8_t *body, size_t n, uint16_t *peer_limit,
#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC)
                             const ch_alpn_protocol *offered, size_t offered_count,
                             uint8_t *selected,
#endif
#ifdef CH_TRUST_WEBPKI
                             int server_name_sent, uint8_t cert_types_offered, uint8_t *cert_type,
#endif
#ifdef CH_TRANSPORT_QUIC
                             const uint8_t **transport_params, size_t *transport_params_len,
#endif
                             uint8_t *alert);

// Certificate body framing: the empty certificate_request_context,
// then the exact-fill CertificateEntry list. On CH_OK *list points
// into body — the raw bytes the CA build's certificate parser
// consumes. The caller seeds *alert; the parser overwrites it when
// it knows better (a nonempty context).
int hsp_parse_certificate(const uint8_t *body, size_t n, const uint8_t **list, size_t *list_len,
                          uint8_t *alert);

// CertificateVerify body: the one offered algorithm, then the
// signature, exact-fill. On CH_OK *sig points into body and lives as
// long as it does. The caller seeds *alert; the parser overwrites it
// only when it knows better (wrong algorithm).
// A TRUST=webpki build takes one more out parameter: on CH_OK *scheme is
// the algorithm the message named, one of SIGALG_RSA_PSS_RSAE_SHA256,
// SIGALG_ECDSA_P256_SHA256 and SIGALG_ECDSA_P384_SHA384, and the caller
// matches it against the leaf key's family. Any other algorithm returns
// CH_EAUTH with handshake_failure, as a scheme the build did not offer
// does in the other builds. That includes SIGALG_RSA_PKCS1_SHA256 and
// SIGALG_RSA_PKCS1_SHA384, which the ClientHello offers for certificate
// signatures and RFC 9846 §4.3.3 forbids in CertificateVerify.
int hsp_parse_certificate_verify(const uint8_t *body, size_t n,
#ifdef CH_TRUST_WEBPKI
                                 uint16_t *scheme,
#endif
                                 const uint8_t **sig, size_t *sig_len, uint8_t *alert);

#endif
