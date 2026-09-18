// RSASSA-PKCS1-v1_5 signature verification (RFC 8017 §8.2.2) for the
// sha256WithRSAEncryption and sha384WithRSAEncryption signatures a public
// CA writes on a certificate. Verify only, with the fixed public exponent
// 65537, the exponentiation rsa.h's rsa_vp1 supplies, and the modulus
// sizes rsa_pss_verify admits. Only a TRUST=webpki object packages this
// file: a device build pins a key and checks CertificateVerify, which is
// RSA-PSS (rsa.h), and never reads a certificate signature.
//
// Every input — the modulus, the digest, the signature — is public, so
// the arithmetic is deliberately variable time and carries none of the
// constant-time burden the secret-handling modules do (compare rsa.h).
#ifndef CH_RSA_PKCS1_H
#define CH_RSA_PKCS1_H

#include <stddef.h>
#include <stdint.h>

// Verifies a PKCS#1 v1.5 signature. n is the raw big-endian modulus,
// n_len bytes, 256 to CH_RSA_MODULUS_MAX (rsa.h: RSA-2048 to RSA-3072, or
// to RSA-4096 under CH_TRUST_WEBPKI), a multiple of 8, and odd; sig must
// be exactly n_len bytes; digest is the SHA-256 (32 bytes)
// or SHA-384 (48 bytes) of the signed content, and digest_len selects
// which DigestInfo the encoded message carries. Returns 1 for a valid
// signature, 0 for anything else: a modulus outside the size range, an
// even modulus, a digest length other than 32 or 48, a signature length
// other than n_len, a signature at or above the modulus, or an encoded
// message that differs from the expected one in any byte.
int rsa_pkcs1_verify(const uint8_t *n, size_t n_len, const uint8_t *digest, size_t digest_len,
                     const uint8_t *sig, size_t sig_len);

#endif
