// NIST P-384 ECDSA signature verification (FIPS 186-4 / SEC 1). No
// signing, no scalar secrets: every input — the peer's public key, the
// message hash, the wire signature — is public, so the arithmetic is
// deliberately variable time and carries none of the constant-time
// burden the rest of this codebase does. The TRUST=webpki build uses it
// for the chain signatures a public CA writes with ecdsa_secp384r1_sha384.
#ifndef CH_P384_H
#define CH_P384_H

#include <stddef.h>
#include <stdint.h>

#include "p384_field.h" // P384_LEN: the byte length of one coordinate or scalar

#define P384_PUB_LEN (2 * P384_LEN) // the raw uncompressed point, X||Y

// Returns 1 for a valid signature, 0 for anything else. pub is the raw
// uncompressed point (X||Y, 96 bytes); msg_hash is exactly 48 bytes, so
// a caller holding a digest of another length truncates or left-pads
// it first (FIPS 186-4 §6.4); sig is the DER ECDSA-Sig-Value from the
// wire. Verification only — all inputs are public, so variable-time
// arithmetic is acceptable and stated.
int p384_ecdsa_verify(const uint8_t pub[P384_PUB_LEN], const uint8_t msg_hash[P384_LEN],
                      const uint8_t *sig_der, size_t sig_len);

#endif
