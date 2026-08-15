// NIST P-256 ECDSA signature verification (FIPS 186-4 / SEC 1). No
// signing, no scalar secrets: every input — the peer's public key, the
// transcript hash, the wire signature — is public, so the arithmetic is
// deliberately variable time and carries none of the constant-time
// burden the rest of this codebase does.
#ifndef MS_P256_H
#define MS_P256_H

#include <stddef.h>
#include <stdint.h>

// Returns 1 for a valid signature, 0 for anything else. pub is the raw
// uncompressed point (X||Y, 64 bytes); sig is the DER ECDSA-Sig-Value
// from the wire. Verification only — all inputs are public, so
// variable-time arithmetic is acceptable and stated.
int p256_ecdsa_verify(const uint8_t pub[64], const uint8_t msg_hash[32], const uint8_t *sig_der,
                      size_t sig_len);

#endif
