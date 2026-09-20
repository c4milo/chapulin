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

// The largest modulus rsa_pss_verify and rsa_pkcs1_verify admit, in
// bytes; the smallest is 256 (RSA-2048) and the step is 8. The device
// modes, raw and CA, stop at 384 (RSA-3072). A TRUST=webpki
// build (-DCH_TRUST_WEBPKI) admits 512 (RSA-4096), because a public
// chain ends at a root that size: GTS Root R1 is RSA-4096, measured in
// docs/webpki.md under "Bounds". rsa_mont.c sizes its limb arrays from
// this value, so it also sets rsa_vp1's stack frame.
#ifndef CH_RSA_MODULUS_MAX
#ifdef CH_TRUST_WEBPKI
#define CH_RSA_MODULUS_MAX 512
#else
#define CH_RSA_MODULUS_MAX 384
#endif
#endif

// Verifies a PSS signature. n is the raw big-endian modulus, n_len bytes,
// 256 to CH_RSA_MODULUS_MAX (RSA-2048 to RSA-3072, or to RSA-4096 under
// CH_TRUST_WEBPKI) and a multiple of 8; sig must be exactly n_len bytes;
// msg_hash is the 32-byte SHA-256 of the signed content. Returns 1 for a
// valid rsa_pss_rsae_sha256 signature (MGF1-SHA256, saltLen = 32), 0 for
// anything else.
int rsa_pss_verify(const uint8_t *n, size_t n_len, const uint8_t msg_hash[32], const uint8_t *sig,
                   size_t sig_len);

// Internal split boundary, defined in rsa_mont.c: em = sig^65537 mod n
// (RSAVP1), all values n_len big-endian bytes. rsa.c handles every check;
// the caller here guarantees sig < n. Not part of the public API.
void rsa_vp1(const uint8_t *n, size_t n_len, const uint8_t *sig, uint8_t *em);

#endif
