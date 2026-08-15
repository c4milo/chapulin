// Handshake message construction and the wire constants both build and
// parse sides share. The only message a PSK client ever builds besides
// Finished is the ClientHello, so that is what lives here.
#ifndef MS_HSMSG_H
#define MS_HSMSG_H

#include <stddef.h>
#include <stdint.h>

#include "tls.h"

// Handshake message types.
#define HS_CLIENT_HELLO 1
#define HS_SERVER_HELLO 2
#define HS_NEW_SESSION_TICKET 4
#define HS_ENCRYPTED_EXTENSIONS 8
#define HS_CERTIFICATE 11
#define HS_CERTIFICATE_REQUEST 13
#define HS_FINISHED 20
#define HS_KEY_UPDATE 24
#define HS_MESSAGE_HASH 254 // synthetic, transcript-only (HRR)

// Extension codes.
#define EXT_SUPPORTED_GROUPS 10
#define EXT_RECORD_SIZE_LIMIT 28
#define EXT_PRE_SHARED_KEY 41
#define EXT_SUPPORTED_VERSIONS 43
#define EXT_COOKIE 44
#define EXT_PSK_MODES 45
#define EXT_KEY_SHARE 51

#define TLS13 0x0304
#define SUITE_CHACHA20_POLY1305_SHA256 0x1303
#define GROUP_X25519 0x001d

// The binders list is a fixed 35-byte tail here (one 32-byte binder):
// u16 list length, u8 binder length, 32 binder bytes.
#define CH_BINDERS_TAIL 35

// Builds a complete ClientHello handshake message (header included) with
// a zeroed binder. rsl is our record_size_limit; cookie echoes an HRR
// cookie (NULL first flight). Returns the total length, or 0 if cap is
// short. The binder occupies the final 32 bytes; the transcript for it
// covers the first (length - CH_BINDERS_TAIL) bytes.
size_t hs_build_ch(uint8_t *out, size_t cap, const ms_cfg *cfg, const uint8_t pub[32],
                   const uint8_t random32[32], uint16_t rsl, const uint8_t *cookie,
                   size_t cookielen);

#endif
