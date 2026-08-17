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

// out gets out_len bytes, out_len <= 255*32 per RFC 5869; chapulin never
// asks for more than 32.
void hkdf_expand(const uint8_t prk[SHA256_LEN], const uint8_t *info, size_t info_len, uint8_t *out,
                 size_t out_len);

// HKDF-Expand-Label(secret, "tls13 " + label, ctx, out_len). label excludes
// the "tls13 " prefix and is at most 12 bytes — the longest TLS 1.3 uses.
#define HKDF_LABEL_MAX 12
void hkdf_expand_label(const uint8_t secret[SHA256_LEN], const char *label, const uint8_t *ctx,
                       size_t ctx_len, uint8_t *out, size_t out_len);

// Derive-Secret(secret, label, transcript-hash).
void hkdf_derive_secret(const uint8_t secret[SHA256_LEN], const char *label,
                        const uint8_t hash[SHA256_LEN], uint8_t out[SHA256_LEN]);

#endif
