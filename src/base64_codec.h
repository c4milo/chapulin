// RFC 4648 text to bytes and back, for the callers that hold whole
// values in memory: jws.c's base64url (section 5, no padding) and
// scram.c's base64 (section 4, padded). pem.c does not call it: a PEM
// body has line breaks, and pem.c decodes it a character at a time
// through base64.h's class.
//
// The bytes may be secret. A JWS is a bearer token: whoever reads it can
// present it. A SCRAM proof is derived from a password. So no branch and
// no memory index reads a byte or a character. The loops branch on the
// lengths, the padded decoder branches on the count of '=' at the end of
// its text, and each decoder branches once at its end on whether any
// character was refused, which the caller sees.
#ifndef CH_BASE64_CODEC_H
#define CH_BASE64_CODEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef CH_JWS
// jws.h's ch_base64url_encode, under its contract.
int base64url_encode(const uint8_t *in, size_t in_len, uint8_t *text, size_t text_cap,
                     size_t *text_len);

// jws.h's ch_base64url_decode, under its contract.
int base64url_decode(const uint8_t *text, size_t text_len, uint8_t *out, size_t out_cap,
                     size_t *out_len);
#endif

#ifdef CH_SCRAM
// scram.h's ch_base64_encode, under its contract.
int base64_encode(const uint8_t *in, size_t in_len, uint8_t *text, size_t text_cap,
                  size_t *text_len);

// scram.h's ch_base64_decode, under its contract.
int base64_decode(const uint8_t *text, size_t text_len, uint8_t *out, size_t out_cap,
                  size_t *out_len);
#endif

#endif
