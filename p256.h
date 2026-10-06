// NIST P-256 ECDSA signature verification (FIPS 186-4 / SEC 1). No
// signing, no scalar secrets: every input — the peer's public key, the
// transcript hash, the wire signature — is public, so the arithmetic is
// deliberately variable time and carries none of the constant-time
// burden the rest of this codebase does. A device object computes it on
// p256.c's own 32-bit limbs. A host object (-DCH_CPU_RUNTIME, cpu_cfg.h)
// computes it on the wide P-256 field's 64-bit limbs, with points of its
// own that are variable time too (p256_wide_verify.h): the verdict is
// the same for every input, and no bit of ch_cfg.cpu picks between the
// two (docs/decisions.md 96 and 104).
#ifndef CH_P256_H
#define CH_P256_H

#include <stddef.h>
#include <stdint.h>

// Returns 1 for a valid signature, 0 for anything else. pub is the raw
// uncompressed point (X||Y, 64 bytes); sig is the DER ECDSA-Sig-Value
// from the wire. Verification only — all inputs are public, so
// variable-time arithmetic is acceptable and stated.
int p256_ecdsa_verify(const uint8_t pub[64], const uint8_t msg_hash[32], const uint8_t *sig_der,
                      size_t sig_len);

#endif
