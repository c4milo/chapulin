// RFC 7468 textual encoding, decode side only, for provisioning. Reads
// one CERTIFICATE block and writes out the DER it carries.
//
// Decoding is not authenticating. Nothing here reads a signature, and a
// block that decodes proves nothing about who sent it. The caller
// trusts these bytes because an operator pushed them over the TLS
// session (docs/rotation.md), exactly as it trusts a raw pin.
//
// One block per call, and a second block is an error rather than
// something to ignore. The two pin slots are ordered in time: slot A
// holds the current key and slot B the staged next one. A PEM file's
// blocks are ordered by certificate hierarchy. Nothing in a two-block
// file says which ordering applies, so the caller names the slot with a
// second call instead of the decoder choosing.
#ifndef CH_PEM_H
#define CH_PEM_H

#include <stddef.h>
#include <stdint.h>

#include "cfg.h"

// Largest PEM text the decoder reads. Derived from CH_X509_MAX so the
// cap and the grammar agree: every certificate the parser admits must
// fit at every line width the decoder accepts. Base64 spends four
// characters per three DER bytes; the terminator budget of two bytes
// per four characters covers CRLF wrapping down to four characters a
// line; 64 bytes cover the two boundary lines and their terminators.
// x509.h's bounds on CH_X509_MAX, restated because this header does
// not include x509.h and a consumer build can override the cap: the
// derivation below is only sized for this range.
#ifndef __cplusplus
_Static_assert(CH_X509_MAX >= 512, "the smallest real certificate needs room");
_Static_assert(CH_X509_MAX <= 0x3fe0, "a certificate must fit one handshake message");
#endif

#define CH_PEM_BODY_MAX (4 * ((CH_X509_MAX + 2) / 3))
#define CH_PEM_MAX (CH_PEM_BODY_MAX + (CH_PEM_BODY_MAX / 4) * 2 + 64)

// Decodes one "-----BEGIN CERTIFICATE-----" block into der.
//
// Accepts CR and LF anywhere in the body at any line width, canonical
// RFC 4648 padding, and nothing but CR and LF after the END line.
// Rejects everything else, including explanatory text before the BEGIN
// line and a second block after the END line.
//
// Decoding is not authenticating: a block that decodes proves nothing
// about who sent it (the header above says why).
//
// Returns CH_OK with *der_len set, or CH_EINVAL with *der_len 0. On
// CH_EINVAL the der array holds unspecified bytes: the length is the
// whole contract and the caller must not read past it. Certificate
// bytes are public, so nothing here is wiped.
int pem_decode_certificate(const uint8_t *pem, size_t pem_len, uint8_t der[CH_X509_MAX],
                           size_t *der_len);

#endif
