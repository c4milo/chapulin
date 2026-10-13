// RFC 7468's textual form, decode side only. Reads one block and writes
// out the DER it carries. A block has one of four labels:
//  - CERTIFICATE, RFC 7468 section 5;
//  - PRIVATE KEY, section 10, a PKCS #8 PrivateKeyInfo;
//  - EC PRIVATE KEY, RFC 5915 section 4, a SEC 1 ECPrivateKey;
//  - EC PARAMETERS, the ECParameters that `openssl ecparam -genkey`
//    writes above an EC PRIVATE KEY block.
// pem_blocks.h reads a run of CERTIFICATE blocks one block at a time
// through pem_read_block.
//
// A block that decodes is not authenticated. Nothing here reads a
// signature, and a block that decodes proves nothing about who sent it.
// The caller trusts these bytes because an operator placed them, over
// the TLS session (docs/rotation.md) or in the host's own files. It
// trusts them exactly as it trusts a raw pin.
//
// pem_decode_certificate reads one block per call, and a second block
// is an error rather than something to ignore. The two pin slots are
// ordered in time: slot A holds the current key and slot B the staged
// next one. A PEM file's blocks are ordered by certificate hierarchy.
// Nothing in a two-block file says which order applies. So the caller
// names the slot with a second call, and the decoder chooses nothing.
#ifndef CH_PEM_H
#define CH_PEM_H

#include <stddef.h>
#include <stdint.h>

#include "buf.h"
#include "cfg.h"

// Largest PEM text the decoder reads. Derived from CH_X509_MAX so the
// cap and the grammar agree: every certificate the parser admits fits
// at every line width of four characters or more, CRLF included. A
// narrower wrap spends more bytes on terminators than the budget
// below holds, so a full-size certificate wrapped at one character is
// over the cap — rejected for its size, not its width. Base64 spends four
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

// The longest private key DER that pem_files.c decodes. It is a PKCS #8
// PrivateKeyInfo whose ECPrivateKey carries both optional fields, the
// curve and the public key. That is a 3-byte SEQUENCE header and 147
// bytes of content. The content is version 3, the AlgorithmIdentifier
// 21, the OCTET STRING header 2 and the ECPrivateKey 121. The
// ECPrivateKey is its own 2-byte header, version 3, the scalar 34, the
// curve 12 and the public key 70.
#define CH_PEM_KEY_DER_MAX 150
// The DER of the one EC PARAMETERS block that a key file may hold above
// its EC PRIVATE KEY block. It is the namedCurve OBJECT IDENTIFIER of
// prime256v1, 10 bytes (RFC 5480 section 2.1.1).
#define CH_PEM_PARAMETERS_DER_MAX 10
// The text cap of a key file, derived as CH_PEM_MAX is. It holds the
// key's block and an EC PARAMETERS block above it. For each block it
// counts the base64 body, two terminator bytes per four characters, and
// 64 bytes for the boundary lines and their terminators. The EC PRIVATE
// KEY boundary lines, 30 and 28 bytes, take 62 bytes with a CRLF after
// each. They are the longest of the four labels and fit the 64 bytes.
#define CH_PEM_KEY_BODY_MAX (4 * ((CH_PEM_KEY_DER_MAX + 2) / 3))
#define CH_PEM_PARAMETERS_BODY_MAX (4 * ((CH_PEM_PARAMETERS_DER_MAX + 2) / 3))
#define CH_PEM_KEY_TEXT_MAX                                                                        \
    (CH_PEM_KEY_BODY_MAX + (CH_PEM_KEY_BODY_MAX / 4) * 2 + 64 + CH_PEM_PARAMETERS_BODY_MAX +       \
     (CH_PEM_PARAMETERS_BODY_MAX / 4) * 2 + 64)

// The labels pem_read_block takes, as indexes into pem.c's table.
#define PEM_LABEL_CERTIFICATE 0    // CERTIFICATE, RFC 7468 section 5
#define PEM_LABEL_PRIVATE_KEY 1    // PRIVATE KEY, RFC 7468 section 10
#define PEM_LABEL_EC_PRIVATE_KEY 2 // EC PRIVATE KEY, RFC 5915 section 4
#define PEM_LABEL_EC_PARAMETERS 3  // EC PARAMETERS, as OpenSSL writes it
#define PEM_LABEL_COUNT 4

// Reads one block at r's position: the BEGIN line of label, a line
// terminator, the base64 body, and the END line of the same label. A
// line terminator is LF, or CR then LF. The body admits CR and LF
// anywhere, at any line width, and RFC 4648's canonical pad characters.
// Leaves r after the END line's last dash: what may follow it is the
// caller's rule. Appends the DER to der.
//
// Returns 1, or 0 for any deviation:
//  - a boundary that is not label's;
//  - a byte outside the alphabet;
//  - pad characters that RFC 4648 section 3.5 does not admit;
//  - an empty body, or input that ends before the END line;
//  - a der whose room the bytes outgrow (its sticky error).
// On 0, r and der stand at positions the caller must not read past, and
// der's room holds unspecified bytes after the length it had.
//
// A body may carry a secret, a private key. The base64 accumulator holds
// its bits. This call wipes the accumulator before it returns, on every
// path. So the only copies left are the caller's text and the DER in
// der.
int pem_read_block(rbuf *r, uint8_t label, wbuf *der);

// Whether r's next bytes are "-----BEGIN ", the 11 bytes that open RFC
// 7468 section 3's pre-encapsulation boundary of every label. Reads no
// byte after them. Reads a copy of r, so r does not move. Returns 1 or 0.
int pem_begins_boundary(const rbuf *r);

// Reads the whole of pem as exactly one block of label: the block at the
// first byte, then nothing but CR and LF. Appends the DER to der. Returns
// 1 or 0, as pem_read_block does. The caller caps pem_len.
int pem_decode_one(const uint8_t *pem, size_t pem_len, uint8_t label, wbuf *der);

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
