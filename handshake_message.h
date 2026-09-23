// Handshake message construction and the wire constants both build and
// parse sides share. The only message the client ever builds besides
// Finished is the ClientHello, so that is what lives here.
#ifndef CH_HANDSHAKE_MESSAGE_H
#define CH_HANDSHAKE_MESSAGE_H

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"
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
#define EXT_RECORD_SIZE_LIMIT 28
#define EXT_PRE_SHARED_KEY 41
#define EXT_SUPPORTED_VERSIONS 43
#define EXT_COOKIE 44
#define EXT_PSK_MODES 45
#define EXT_KEY_SHARE 51
// quic_transport_parameters (RFC 9001 §8.2, rfc9001.txt:1921-1923).
// Declared in every build, as the two alert descriptions below are, so
// a TRANSPORT=tls build can answer unsupported_extension for an
// extension it understands on a transport that is not QUIC
// (rfc9001.txt:1945-1949).
#define EXT_QUIC_TRANSPORT_PARAMS 0x39

#define TLS13 0x0304
#define SUITE_CHACHA20_POLY1305_SHA256 0x1303
// TLS_AES_128_GCM_SHA256, which RFC 9846 section 9.1 makes mandatory to
// implement (rfc9846.txt:4540-4543). Only a -DCH_SUITE_AES_GCM build
// offers or selects it, and ct.h refuses that define unless the build has
// hardware AES and asserts its timing.
#define SUITE_AES_128_GCM_SHA256 0x1301

// The one group this build offers (its code point is one of cfg.h's
// two CH_GROUP_* values), and its share size on each side. The hybrid
// share order is RFC 10024's: the ML-KEM bytes come first on both
// sides, despite the group name.
#ifdef CH_KEX_PQ
#include "mlkem.h"
#define CH_KEX_GROUP CH_GROUP_X25519MLKEM768
#define CH_KEX_CLIENT_SHARE (MLKEM_EK_LEN + 32)
#define CH_KEX_SERVER_SHARE (MLKEM_CT_LEN + 32)
#else
#define CH_KEX_GROUP CH_GROUP_X25519
#define CH_KEX_CLIENT_SHARE 32
#define CH_KEX_SERVER_SHARE 32
#endif
// A KEX=pq TRUST=webpki client offers a second group (docs/decisions.md
// entry 39). supported_groups lists X25519MLKEM768 and then x25519, and
// the first hello carries a key share for X25519MLKEM768 alone, so a
// server that lacks the hybrid answers with a HelloRetryRequest naming
// x25519 and the retry hello carries an x25519 share. ch_cfg.require_pq
// drops x25519 from the list, so that caller's hello is the one-group
// hello every other KEX=pq build sends. Every other build offers
// CH_KEX_GROUP alone. cfg.h defines CH_KEX_TWO_GROUPS, because the
// session and parser headers that declare its fields sit below this one.
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
// largest cookie an HRR may hand back, and the build's key share.
// Measured against hs_build_client_hello: 617 classic, 1801 for pq. The
// hello is built whole into one TX staging array, so CH_TX_STAGE must
// hold this; handshake.c asserts it where both constants are visible.
//
// A TRUST=webpki build adds two more terms. The server_name extension at
// the longest hostname: type and length words (4), the ServerNameList
// length (2), the name_type byte (1), the HostName length (2) and
// CH_HOSTNAME_MAX bytes, 262 in all. And the ALPN extension at the
// longest offer: type and length words (4), the ProtocolNameList length
// (2), then CH_ALPN_MAX names of one length byte and CH_ALPN_NAME_MAX
// bytes each, 270 in all. It also offers five signature schemes instead
// of one, 8 bytes more, but those bytes sit in the arm a config with no
// psk takes. That arm's 16-byte signature_algorithms extension stays
// shorter than the 47 + CH_TICKET_ID_MAX bytes of the pre_shared_key
// extension the other arm carries. So the largest hello is still the
// pre_shared_key arm, now with both extensions: 1149 classic, and 2335
// for pq, whose supported_groups carries the second group, measured by
// test/webpki_session_test.c.
// A TRANSPORT=quic build adds two more terms. It drops the 6-byte
// record_size_limit extension, because RFC 9001 §4.1.3 removes the
// record layer that extension sizes (rfc9001.txt:462-464), and it sends
// quic_transport_parameters in its place: type and length words (4) and
// a body of at most CH_TRANSPORT_PARAMS_MAX bytes. It also sends the
// ALPN extension in every trust mode, because §8.1 makes ALPN mandatory
// there (rfc9001.txt:1891-1895), so the ALPN term is no longer the
// webpki build's alone.
//
// A CH_KEX_TWO_GROUPS build adds one more term: the second NamedGroup
// in supported_groups, 2 bytes.
//
// Each term is 0 in a build that sends nothing for it, so one sum
// serves every combination and a TRANSPORT=tls build keeps the value it
// had: 617 raw classic, 1149 webpki classic.
#if defined(CH_TRUST_WEBPKI) || defined(CH_TRANSPORT_QUIC)
#define CH_HELLO_ALPN_MAX (4 + 2 + CH_ALPN_MAX * (1 + CH_ALPN_NAME_MAX))
#else
#define CH_HELLO_ALPN_MAX 0
#endif
#ifdef CH_TRUST_WEBPKI
#define CH_HELLO_SERVER_NAME_MAX (4 + 2 + 1 + 2 + CH_HOSTNAME_MAX)
#else
#define CH_HELLO_SERVER_NAME_MAX 0
#endif
#ifdef CH_TRANSPORT_QUIC
#define CH_HELLO_TRANSPORT_MAX (4 + CH_TRANSPORT_PARAMS_MAX - 6)
#else
#define CH_HELLO_TRANSPORT_MAX 0
#endif
#ifdef CH_KEX_TWO_GROUPS
#define CH_HELLO_SECOND_GROUP_MAX 2
#else
#define CH_HELLO_SECOND_GROUP_MAX 0
#endif
#define CH_HELLO_MAX                                                                               \
    (137 + CH_HELLO_SERVER_NAME_MAX + CH_HELLO_ALPN_MAX + CH_HELLO_TRANSPORT_MAX +                 \
     CH_HELLO_SECOND_GROUP_MAX + CH_TICKET_ID_MAX + HSP_COOKIE_MAX + CH_KEX_CLIENT_SHARE)

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
// missing_extension, RFC 9846 §6 (rfc9846.txt:3816). A TRANSPORT=quic
// build writes it for an EncryptedExtensions that carries no
// quic_transport_parameters, which RFC 9001 §8.2 makes an error of type
// 0x016d (rfc9001.txt:1930-1936). §4.8's 0x0100 conversion reaches that
// code from this description and no other.
#define ALERT_MISSING_EXTENSION 109
#define ALERT_UNSUPPORTED_EXTENSION 110
// no_application_protocol, RFC 9846 §6 (rfc9846.txt:3823). A
// TRANSPORT=quic build writes it whenever ALPN negotiation fails, which
// RFC 9001 §8.1 makes error 0x0178 for a client (rfc9001.txt:1896-1902)
// and which §4.8's conversion reaches from this description and no
// other. A TRANSPORT=tls build keeps illegal_parameter there.
//
// Both descriptions are declared in every build, as the descriptions
// above are, so proof/eeparse_harness.c reads one alert list on both
// transports.
#define ALERT_NO_APPLICATION_PROTOCOL 120

// The binders list is a fixed 35-byte tail here (one 32-byte binder):
// u16 list length, u8 binder length, 32 binder bytes.
#define CH_BINDERS_TAIL 35

// Builds a complete ClientHello handshake message (header included). In
// PSK mode (cfg->psk set) the pre_shared_key extension comes last with a
// zeroed binder: the binder occupies the final 32 bytes and the binder
// transcript covers the first (length - CH_BINDERS_TAIL) bytes. In
// pinned-key mode the hello offers signature_algorithms instead and has
// no binder. record_size_limit is the limit we advertise; cookie echoes
// an HRR cookie (NULL first flight). Returns the total length, or 0 if
// cap is short.
// A TRUST=webpki build puts server_name first in the extension list,
// carrying cfg->hostname, whose length the caller holds to
// CH_HOSTNAME_MAX (ch_connect checks it with webpki_hostname_ok), and
// its signature_algorithms lists the five schemes above. It writes the
// ALPN extension next when cfg->alpn_count is not 0, listing
// cfg->alpn_protocols in the caller's order (RFC 7301 §3.1).
// The hybrid build's share carries the ML-KEM encapsulation key ahead
// of the x25519 public value, so its builder takes both.
// A CH_KEX_TWO_GROUPS build also takes share_group, the one group its
// key_share carries: CH_KEX_GROUP for the first hello and for a retry
// that asked only for a cookie, with ek and pub as the hybrid share, or
// CH_GROUP_X25519 for the retry a HelloRetryRequest naming x25519 asked
// for, with pub alone and ek unread. Its supported_groups lists
// CH_KEX_GROUP and then CH_GROUP_X25519, or CH_KEX_GROUP alone when
// cfg->require_pq is set.
size_t hs_build_client_hello(uint8_t *out, size_t cap, const ch_cfg *cfg,
#ifdef CH_KEX_TWO_GROUPS
                             uint16_t share_group,
#endif
#ifdef CH_KEX_PQ
                             const uint8_t ek[MLKEM_EK_LEN],
#endif
                             const uint8_t pub[32], const uint8_t random32[32],
                             uint16_t record_size_limit, const uint8_t *cookie, size_t cookie_len);

#endif
