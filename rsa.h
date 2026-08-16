// RSA-PSS signature verification (RFC 8017, rsa_pss_rsae_sha256). Verify
// only, with the fixed public exponent 65537, MGF1-SHA256, and salt
// length 32. Every input — the modulus, the signature, the message hash
// — is public, so the arithmetic is deliberately variable time and
// carries none of the constant-time burden the secret-handling modules
// do (compare p256.h).
#ifndef CH_RSA_H
#define CH_RSA_H

#include <stddef.h>
#include <stdint.h>

// Verifies a PSS signature. n is the raw big-endian modulus, nlen bytes,
// 256 to 384 (RSA-2048 to RSA-3072) and a multiple of 8; sig must be
// exactly nlen bytes; msg_hash is the 32-byte SHA-256 of the signed
// content. Returns 1 for a valid rsa_pss_rsae_sha256 signature
// (MGF1-SHA256, saltLen = 32), 0 for anything else.
int rsa_pss_verify(const uint8_t *n, size_t nlen, const uint8_t msg_hash[32], const uint8_t *sig,
                   size_t siglen);

// Internal split boundary, defined in rsa_mont.c: em = sig^65537 mod n
// (RSAVP1), all values nlen big-endian bytes. rsa.c handles every check;
// the caller here guarantees sig < n. Not part of the public API.
void rsa_vp1(const uint8_t *n, size_t nlen, const uint8_t *sig, uint8_t *em);

#endif
