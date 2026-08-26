// Handshake message construction and the wire constants both build and
// parse sides share. The only message the client ever builds besides
// Finished is the ClientHello, so that is what lives here.
#ifndef CH_HANDSHAKE_MESSAGE_H
#define CH_HANDSHAKE_MESSAGE_H

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"

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
#define EXT_SUPPORTED_GROUPS 10
#define EXT_SIGNATURE_ALGORITHMS 13
#define EXT_RECORD_SIZE_LIMIT 28
#define EXT_PRE_SHARED_KEY 41
#define EXT_SUPPORTED_VERSIONS 43
#define EXT_COOKIE 44
#define EXT_PSK_MODES 45
#define EXT_KEY_SHARE 51

#define TLS13 0x0304
#define SUITE_CHACHA20_POLY1305_SHA256 0x1303
#define GROUP_X25519 0x001d
#define GROUP_X25519MLKEM768 0x11ec

// The one group this build offers, and its share size on each side.
// The hybrid share order is RFC 10024's: the ML-KEM bytes come first
// on both sides, despite the group name.
#ifdef CH_KEX_PQ
#include "mlkem.h"
#define CH_KEX_GROUP GROUP_X25519MLKEM768
#define CH_KEX_CLIENT_SHARE (MLKEM_EK_LEN + 32)
#define CH_KEX_SERVER_SHARE (MLKEM_CT_LEN + 32)
#else
#define CH_KEX_GROUP GROUP_X25519
#define CH_KEX_CLIENT_SHARE 32
#define CH_KEX_SERVER_SHARE 32
#endif
#define SIGALG_ECDSA_P256_SHA256 0x0403
#define SIGALG_RSA_PSS_RSAE_SHA256 0x0804

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
#define CH_HELLO_MAX (137 + CH_TICKET_ID_MAX + HSP_COOKIE_MAX + CH_KEX_CLIENT_SHARE)

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
#define ALERT_ILLEGAL_PARAMETER 47
#define ALERT_UNKNOWN_CA 48
#define ALERT_DECODE_ERROR 50
#define ALERT_DECRYPT_ERROR 51
#define ALERT_INTERNAL_ERROR 80
#define ALERT_UNSUPPORTED_EXTENSION 110

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
// The hybrid build's share carries the ML-KEM encapsulation key ahead
// of the x25519 public value, so its builder takes both.
size_t hs_build_client_hello(uint8_t *out, size_t cap, const ch_cfg *cfg,
#ifdef CH_KEX_PQ
                             const uint8_t ek[MLKEM_EK_LEN],
#endif
                             const uint8_t pub[32], const uint8_t random32[32],
                             uint16_t record_size_limit, const uint8_t *cookie, size_t cookie_len);

#endif
