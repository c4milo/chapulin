// Parsers for the two handshake messages that carry attacker-chosen
// bytes before the peer is authenticated: ServerHello (including
// HelloRetryRequest) and EncryptedExtensions. Pure functions over caller
// buffers — no I/O, no session state; handshake.c decides what the
// results mean. External linkage so proof, fuzz, and strictness-test
// builds reach the parsers without the state machine; the packaged
// library object localizes them like every other internal symbol.
#ifndef CH_HANDSHAKE_PARSER_H
#define CH_HANDSHAKE_PARSER_H

#include <stddef.h>
#include <stdint.h>

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
    // rather than from that constant.
    uint16_t group;
    uint8_t server_pub[X25519_LEN];
#ifdef CH_KEX_PQ
    // The ML-KEM ciphertext, MLKEM_CT_LEN bytes into the caller's
    // message — like cookie, the pointer dies at the next record read;
    // the handshake decapsulates before one runs.
    const uint8_t *server_ct;
#endif
    const uint8_t *cookie; // into the caller's message; NULL if absent
    size_t cookie_len;
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
// §4.3). A TRUST=webpki build also admits one server_name with empty
// extension_data, the acknowledgement RFC 6066 §3 allows for the
// server_name its ClientHello sent. A server_name that carries data
// there has the wrong length, and the parser writes decode_error
// (RFC 9846 §6). Returns CH_OK or CH_EPROTO.
int hsp_parse_encrypted_exts(const uint8_t *body, size_t n, uint16_t *peer_limit, uint8_t *alert);

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
// signatures and RFC 9846 §4.4.3 forbids in CertificateVerify.
int hsp_parse_certificate_verify(const uint8_t *body, size_t n,
#ifdef CH_TRUST_WEBPKI
                                 uint16_t *scheme,
#endif
                                 const uint8_t **sig, size_t *sig_len, uint8_t *alert);

#endif
