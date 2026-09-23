// HMAC-SHA-256 (RFC 2104), HKDF (RFC 5869), and the TLS 1.3 label scheme
// (RFC 9846 §7.1). One file because TLS 1.3 uses them as one unit: every
// key in the protocol is an HKDF-Expand-Label of some HKDF-Extract output,
// and Finished is the lone bare-HMAC user.
#ifndef CH_HKDF_H
#define CH_HKDF_H

#include <stddef.h>
#include <stdint.h>

#include "sha256.h"

void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                 uint8_t out[SHA256_LEN]);

void hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len,
                  uint8_t prk[SHA256_LEN]);

// out gets out_len bytes, out_len <= 255*32 per RFC 5869. The key
// schedule asks for 32; an EXPORTER=on build asks for up to CH_EXPORT_MAX
// through ch_export, which is eight blocks.
void hkdf_expand(const uint8_t prk[SHA256_LEN], const uint8_t *info, size_t info_len, uint8_t *out,
                 size_t out_len);

// HKDF-Expand-Label(secret, "tls13 " + label, ctx, out_len). label excludes
// the "tls13 " prefix and is at most HKDF_LABEL_MAX bytes.
//
// The default 12 is the longest label TLS 1.3 itself writes. A build may
// raise it, and the EXPORTER axis does: RFC 9846 §7.5 lets the caller
// choose the exporter's label, and RFC 9266's is "EXPORTER-Channel-Binding"
// at 24 bytes. The cap is a build parameter rather than two entry points
// because the only thing that changes is the size of one stack buffer
// below, so a device build that never exports keeps the 12 it had.
#ifndef HKDF_LABEL_MAX
#define HKDF_LABEL_MAX 12
#endif
_Static_assert(HKDF_LABEL_MAX >= 12, "TLS 1.3's own labels need 12 bytes");
// HkdfLabel's label vector carries a one-byte length that counts the
// "tls13 " prefix too, so the cap has a ceiling as well as a floor.
_Static_assert(HKDF_LABEL_MAX <= 255 - 6, "the label vector's length is one byte, prefix included");

// The longest info any caller here passes to hkdf_expand, which is the
// one hkdf_expand_label builds: two length bytes, the label vector's own
// length byte, "tls13 ", the label, the context's length byte and a
// transcript hash. It was written as 64 while the label cap was fixed;
// deriving it is what lets the cap move without a second number to keep
// in step.
#define HKDF_INFO_MAX (2 + 1 + 6 + HKDF_LABEL_MAX + 1 + SHA256_LEN)
void hkdf_expand_label(const uint8_t secret[SHA256_LEN], const char *label, const uint8_t *ctx,
                       size_t ctx_len, uint8_t *out, size_t out_len);

// Derive-Secret(secret, label, transcript-hash).
void hkdf_derive_secret(const uint8_t secret[SHA256_LEN], const char *label,
                        const uint8_t hash[SHA256_LEN], uint8_t out[SHA256_LEN]);

#endif
