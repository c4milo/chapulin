// Handshake message construction and the wire constants both build and
// parse sides share. The only message the client ever builds besides
// Finished is the ClientHello, so that is what lives here.
#ifndef CH_HANDSHAKE_MESSAGE_H
#define CH_HANDSHAKE_MESSAGE_H

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
#include "suite.h"
#ifdef CH_TRUST_WEBPKI
#include "webpki.h"
#endif

// Handshake message types.
#define HS_CLIENT_HELLO 1
#define HS_SERVER_HELLO 2
#define HS_NEW_SESSION_TICKET 4
#define HS_ENCRYPTED_EXTENSIONS 8
#define HS_CERTIFICATE 11
#define HS_CERTIFICATE_REQUEST 13
#define HS_CERTIFICATE_VERIFY 15
#define HS_FINISHED 20
#define HS_KEY_UPDATE 24
#define HS_MESSAGE_HASH 254 // synthetic, transcript-only (HRR)

// Extension codes.
#define EXT_SERVER_NAME 0 // RFC 6066 §3; sent by TRUST=webpki builds only
#define EXT_SUPPORTED_GROUPS 10
#define EXT_SIGNATURE_ALGORITHMS 13
#define EXT_ALPN 16 // RFC 7301 §3.1; sent by TRUST=webpki builds only
// RFC 7250 §4.1; sent by TRUST=webpki builds with SPKI pins only
#define EXT_SERVER_CERTIFICATE_TYPE 20
#define EXT_RECORD_SIZE_LIMIT 28
#define EXT_PRE_SHARED_KEY 41
#define EXT_SUPPORTED_VERSIONS 43
#define EXT_COOKIE 44
#define EXT_PSK_MODES 45
#define EXT_KEY_SHARE 51
// quic_transport_parameters (RFC 9001 §8.2, rfc9001.txt:1921-1923).
// Declared in every build, as the two alert descriptions below are, so
// a TRANSPORT=tcp-blocking build can answer unsupported_extension for an
// extension it understands on a transport that is not QUIC
// (rfc9001.txt:1945-1949).
#define EXT_QUIC_TRANSPORT_PARAMS 0x39

#define TLS13 0x0304

// The hybrid share sizes on each side, in RFC 10024's order: the ML-KEM bytes come first
// on both sides, despite the group name. Every client that offers the hybrid
// (CH_KEX_HYBRID, cfg.h) writes and reads them, and so does every server role, which
// holds the hybrid in every build (srv_kex.h).
#if defined(CH_KEX_HYBRID) || defined(CH_ROLE_SERVER)
#include "mlkem.h"
#define CH_HYBRID_CLIENT_SHARE (MLKEM_EK_LEN + 32)
#define CH_HYBRID_SERVER_SHARE (MLKEM_CT_LEN + 32)
#endif

// The one group a raw or ca client offers (Makefile KEX), and its share size on each side.
// A TRUST=webpki client offers both groups and names each one directly, so a webpki build
// defines none of the three, and a client source that reads one fails to compile there.
// No server source reads them: a server role holds both groups whatever KEX says and
// names each one directly (srv_kex.h).
#ifdef CH_KEX_PQ
#define CH_KEX_GROUP CH_GROUP_X25519MLKEM768
#define CH_KEX_CLIENT_SHARE CH_HYBRID_CLIENT_SHARE
#define CH_KEX_SERVER_SHARE CH_HYBRID_SERVER_SHARE
#elif !defined(CH_KEX_TWO_GROUPS)
#define CH_KEX_GROUP CH_GROUP_X25519
#define CH_KEX_CLIENT_SHARE 32
#define CH_KEX_SERVER_SHARE 32
#endif
// A TRUST=webpki client offers both groups in every build (docs/decisions.md entry 53).
// supported_groups lists X25519MLKEM768 and then x25519, and key_share carries an entry
// for each in the same order: the hybrid share, then an x25519 share that repeats the
// x25519 half of the hybrid one. RFC 9954 §3.2 lets a client reuse one algorithm's
// key_exchange value across the KeyShareEntry records of one ClientHello, so the x25519
// entry costs 36 bytes and no second key generation. ch_cfg.require_pq drops x25519 from
// both lists, so that caller's hello is the one-group hello a raw or ca KEX=pq build
// sends. cfg.h defines CH_KEX_TWO_GROUPS, because the session and parser headers that
// declare its fields sit below this one.

// SignatureScheme code points (RFC 9846 §4.3.3). A raw or ca build
// offers the first two, one per build (CH_PIN_SIGALG below). A
// TRUST=webpki build offers all five, because it cannot know which
// family signed the chain the server will send. The two PKCS#1 v1.5
// schemes are offered for certificate signatures only: RFC 9846 §4.3.3
// forbids them in CertificateVerify, and hsp_parse_certificate_verify
// refuses them there.
#define SIGALG_ECDSA_P256_SHA256 0x0403
#define SIGALG_RSA_PSS_RSAE_SHA256 0x0804
#define SIGALG_ECDSA_P384_SHA384 0x0503
#define SIGALG_RSA_PKCS1_SHA256 0x0401
#define SIGALG_RSA_PKCS1_SHA384 0x0501

// The largest ClientHello this build can emit, as three variable terms
// over a 137-byte remainder. The remainder is everything whose size a
// build cannot change: the handshake and body headers, the fixed
// extensions, and the framing of the three variable ones — their type
// and length words, and the pre_shared_key and cookie envelopes. The
// terms are the largest ticket identity a resumption may carry, the
// largest cookie an HRR may hand back, and the key_exchange bytes of the
// first key share. Measured against hs_build_client_hello: 617 classic,
// 1801 for pq. The
// hello is built whole into one TX staging array, so CH_TX_STAGE must
// hold this; handshake.c asserts it where both constants are visible.
//
// A TRUST=webpki build adds two more terms. The server_name extension at
// the longest hostname: type and length words (4), the ServerNameList
// length (2), the name_type byte (1), the HostName length (2) and
// CH_HOSTNAME_MAX bytes, 262 in all. And the ALPN extension at the
// longest offer: type and length words (4), the ProtocolNameList length
// (2), then CH_ALPN_MAX names of one length byte and CH_ALPN_NAME_MAX
// bytes each, 270 in all. And it offers the certificate path in every
// hello, a resuming one too, so that a server that declines the ticket
// can authenticate with a certificate (docs/decisions.md 55): five
// signature schemes, whose extension is type and length words (4), the
// list length (2) and five 2-byte schemes, 16 in all, and the
// server_certificate_type extension a config with SPKI pins adds, type
// and length words (4), the list length (1) and at most two types, 7 in
// all. Those 23 bytes are CH_HELLO_CERT_PATH_MAX. A raw or ca build
// puts its one scheme in the arm a config with no psk takes, 8 bytes
// that stay shorter than the pre_shared_key extension the other arm
// carries, so its term is 0. The largest webpki hello is the
// pre_shared_key arm with both extensions above, the certificate path,
// SPKI pins beside anchors and the two groups below: 2394, measured by
// test/webpki_session_test.c.
// A TRANSPORT=quic-nonblocking build adds two more terms. It drops the 6-byte
// record_size_limit extension, because RFC 9001 §4.1.3 removes the
// record layer that extension sizes (rfc9001.txt:462-464), and it sends
// quic_transport_parameters in its place: type and length words (4) and
// a body of at most CH_TRANSPORT_PARAMS_MAX bytes. It also sends the
// ALPN extension in every trust mode, because §8.1 makes ALPN mandatory
// there (rfc9001.txt:1891-1895), so the ALPN term is no longer the
// webpki build's alone.
//
// A CH_KEX_TWO_GROUPS build takes the hybrid share as its first key share
// and adds two more terms: the second NamedGroup in supported_groups, 2
// bytes, and the second KeyShareEntry, the x25519 one, whose group,
// length and 32-byte value are 36 bytes. A CH_CLIENT_AES_SUITES build
// adds the two AES-GCM cipher suites, 4 bytes more, and its binder can
// be a SHA-384 one, 16 bytes longer than the SHA-256 binder the fixed
// sum counts (CH_HELLO_SHA384_BINDER_MAX).
//
// Each term is 0 in a build that sends nothing for it, so one sum
// serves every combination.
#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC_NONBLOCKING)
#define CH_HELLO_ALPN_MAX (4 + 2 + CH_ALPN_MAX * (1 + CH_ALPN_NAME_MAX))
#else
#define CH_HELLO_ALPN_MAX 0
#endif
#ifdef CH_TRUST_WEBPKI
#define CH_HELLO_SERVER_NAME_MAX (4 + 2 + 1 + 2 + CH_HOSTNAME_MAX)
#define CH_HELLO_CERT_PATH_MAX ((4 + 2 + 5 * 2) + (4 + 1 + 2))
#else
#define CH_HELLO_SERVER_NAME_MAX 0
#define CH_HELLO_CERT_PATH_MAX 0
#endif
#ifdef CH_TRANSPORT_QUIC_NONBLOCKING
#define CH_HELLO_TRANSPORT_MAX (4 + CH_TRANSPORT_PARAMS_MAX - 6)
#else
#define CH_HELLO_TRANSPORT_MAX 0
#endif
#ifdef CH_KEX_TWO_GROUPS
#define CH_HELLO_FIRST_SHARE_MAX CH_HYBRID_CLIENT_SHARE
#define CH_HELLO_SECOND_GROUP_MAX 2
#define CH_HELLO_SECOND_SHARE_MAX (2 + 2 + 32)
#else
#define CH_HELLO_FIRST_SHARE_MAX CH_KEX_CLIENT_SHARE
#define CH_HELLO_SECOND_GROUP_MAX 0
#define CH_HELLO_SECOND_SHARE_MAX 0
#endif
#ifdef CH_CLIENT_AES_SUITES
#define CH_HELLO_AES_SUITES_MAX 4
#define CH_HELLO_SHA384_BINDER_MAX (SHA384_LEN - SHA256_LEN)
#else
#define CH_HELLO_AES_SUITES_MAX 0
#define CH_HELLO_SHA384_BINDER_MAX 0
#endif
#define CH_HELLO_MAX                                                                               \
    (137 + CH_HELLO_SERVER_NAME_MAX + CH_HELLO_ALPN_MAX + CH_HELLO_TRANSPORT_MAX +                 \
     CH_HELLO_CERT_PATH_MAX + CH_HELLO_SECOND_GROUP_MAX + CH_HELLO_SECOND_SHARE_MAX +              \
     CH_HELLO_AES_SUITES_MAX + CH_HELLO_SHA384_BINDER_MAX + CH_TICKET_ID_MAX + HSP_COOKIE_MAX +    \
     CH_HELLO_FIRST_SHARE_MAX)

// Pinned mode verifies exactly one signature algorithm per build: RSA-PSS
// by default (what stock cert-based endpoints hold), ECDSA P-256 with
// -DCH_PIN_ECDSA. The unselected verify module stays out of the packaged
// library object (see PIN in the Makefile).
#ifdef CH_PIN_ECDSA
#define CH_PIN_SIGALG SIGALG_ECDSA_P256_SHA256
#else
#define CH_PIN_SIGALG SIGALG_RSA_PSS_RSAE_SHA256
#endif

// Alert descriptions (RFC 9846 §6).
#define ALERT_CLOSE_NOTIFY 0
#define ALERT_USER_CANCELED 90
#define ALERT_UNEXPECTED_MESSAGE 10
#define ALERT_BAD_RECORD_MAC 20
#define ALERT_RECORD_OVERFLOW 22
#define ALERT_HANDSHAKE_FAILURE 40
#define ALERT_BAD_CERTIFICATE 42
#define ALERT_UNSUPPORTED_CERTIFICATE 43
#define ALERT_CERTIFICATE_REVOKED 44
#define ALERT_CERTIFICATE_EXPIRED 45
#define ALERT_ILLEGAL_PARAMETER 47
#define ALERT_UNKNOWN_CA 48
#define ALERT_DECODE_ERROR 50
#define ALERT_DECRYPT_ERROR 51
// protocol_version, RFC 9846 §6 (rfc9846.txt:3972-3973). A ROLE=server
// build writes it for a ClientHello whose supported_versions does not
// list 0x0304 and for one that carries no supported_versions at all
// (srv_parser.c). A client never sends it: the one version it offers is
// the one it checks the ServerHello for, so a mismatch there is
// illegal_parameter.
#define ALERT_PROTOCOL_VERSION 70
#define ALERT_INTERNAL_ERROR 80
// missing_extension, RFC 9846 §6 (rfc9846.txt:3816). A TRANSPORT=quic-nonblocking
// build writes it for an EncryptedExtensions that carries no
// quic_transport_parameters, which RFC 9001 §8.2 makes an error of type
// 0x016d (rfc9001.txt:1930-1936). §4.8's 0x0100 conversion reaches that
// code from this description and no other.
#define ALERT_MISSING_EXTENSION 109
#define ALERT_UNSUPPORTED_EXTENSION 110
// no_application_protocol, RFC 9846 §6 (rfc9846.txt:3823). A
// TRANSPORT=quic-nonblocking build writes it whenever ALPN negotiation fails, which
// RFC 9001 §8.1 makes error 0x0178 for a client (rfc9001.txt:1896-1902)
// and which §4.8's conversion reaches from this description and no
// other. A TRANSPORT=tcp-blocking build keeps illegal_parameter there.
//
// Both descriptions are declared in every build, as the descriptions
// above are, so proof/eeparse_harness.c reads one alert list on both
// transports.
#define ALERT_NO_APPLICATION_PROTOCOL 120

// The binders list is the hello's tail: u16 list length, u8 binder
// length, and one binder as long as the PSK's hash, 35 bytes for a
// SHA-256 PSK and 51 for a SHA-384 one.
#define CH_BINDERS_TAIL(hash_len) (3 + (hash_len))

// The hash the PSK cfg presents runs under, which names its binder's
// length and the early secret's hash. A ticket's PSK is as long as the
// hash of the suite whose session issued it (rfc9846.txt:3298-3301), so a
// CH_CLIENT_AES_SUITES build, which can hold a ticket from a
// TLS_AES_256_GCM_SHA384 session, reads the hash off that length. Every
// other build presents SHA-256 PSKs alone. The length is public: the
// caller chose it and the binder's length shows it on the wire.
static inline size_t hs_psk_hash_len(const ch_cfg *cfg) {
#ifdef CH_CLIENT_AES_SUITES
    if (cfg->resumption && cfg->psk_len == SHA384_LEN) {
        return SHA384_LEN;
    }
#else
    (void)cfg;
#endif
    return SHA256_LEN;
}

// Builds a complete ClientHello handshake message (header included). In
// PSK mode (cfg->psk set) the pre_shared_key extension comes last with a
// zeroed binder as long as the PSK's hash, hs_psk_hash_len: the binder
// occupies the final hash_len bytes and the binder transcript covers the
// first (length - CH_BINDERS_TAIL(hash_len)) bytes. A raw or
// ca build offers signature_algorithms in pinned-key mode alone, so its
// PSK hello offers no certificate path and a pinned-key hello has no
// binder. record_size_limit is the limit we advertise; cookie echoes an
// HRR cookie (NULL first flight). Returns the total length, or 0 if cap
// is short.
// A TRUST=webpki build puts server_name first in the extension list,
// carrying cfg->hostname, whose length the caller holds to
// CH_HOSTNAME_MAX (ch_connect checks it with webpki_hostname_ok). It
// writes the ALPN extension next when cfg->alpn_count is not 0, listing
// cfg->alpn_protocols in the caller's order (RFC 7301 §3.1). It writes
// signature_algorithms, listing the five schemes above, and then the
// server_certificate_type offer webpki_cert_types_offered makes, in
// every hello, so a PSK hello carries both ahead of pre_shared_key.
// The hybrid share carries the ML-KEM encapsulation key ahead of the
// x25519 public value, so a CH_KEX_HYBRID builder takes both. A
// CH_KEX_TWO_GROUPS build lists CH_GROUP_X25519MLKEM768 and then
// CH_GROUP_X25519 in supported_groups and sends a key share for each in
// that order, the x25519 one over the same pub the hybrid share carries.
// With cfg->require_pq set it lists and shares the hybrid alone.
size_t hs_build_client_hello(uint8_t *out, size_t cap, const ch_cfg *cfg,
#ifdef CH_KEX_HYBRID
                             const uint8_t ek[MLKEM_EK_LEN],
#endif
                             const uint8_t pub[32], const uint8_t random32[32],
                             uint16_t record_size_limit, const uint8_t *cookie, size_t cookie_len);

#endif
