// NIST P-256 ECDSA signature verification (FIPS 186-4 / SEC 1). No
// signing, no scalar secrets: every input — the peer's public key, the
// transcript hash, the wire signature — is public, so the arithmetic is
// deliberately variable time and carries none of the constant-time
// burden the rest of this codebase does. A device object computes it on
// p256.c's own 32-bit words. A host object (-DCH_CPU_RUNTIME, cpu_cfg.h)
// computes it on the wide P-256 field's 64-bit words, with points of its
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

#ifdef CH_CPU_RUNTIME
// p256_ecdsa_verify for one session of a host object, with the session's
// ch_cfg.cpu first (cpu_cfg.h). On x86-64 a value that holds
// CH_CPU_BMI2_ADX runs the check on p256_adx.h's field, whose products
// are MULX's, and every other value runs the call above. The verdict is
// the same for every input. A call holds no session, so a caller that
// holds one passes its value in an argument (docs/decisions.md 171).
//
// Requires: what the plain call requires, and where cpu holds
// CH_CPU_BMI2_ADX, a CPU with BMI2 and ADX, which the session's caller
// states. On a CPU without them the first such instruction faults.
int p256_ecdsa_verify_cpu(uint32_t cpu, const uint8_t pub[64], const uint8_t msg_hash[32],
                          const uint8_t *sig_der, size_t sig_len);
#endif

// p256_ecdsa_verify as a source compiled into both objects calls it for a
// session, with its ch_cfg.cpu first, as rsa.h's RSA_PSS_VERIFY_CPU. A
// host object passes the value to the entry above. A device object holds
// one field, so it calls p256_ecdsa_verify and never evaluates cpu: the
// expression may name a field that build does not declare.
#ifdef CH_CPU_RUNTIME
#define P256_ECDSA_VERIFY_CPU(cpu, ...) p256_ecdsa_verify_cpu((cpu), __VA_ARGS__)
#else
#define P256_ECDSA_VERIFY_CPU(cpu, ...) p256_ecdsa_verify(__VA_ARGS__)
#endif

#if defined(CH_DNSSEC) || defined(CH_JWS)
// p256_ecdsa_verify over the signature a DNSSEC RRSIG carries for
// algorithm 13, and a JWS carries for ES256: r then s, 32 big-endian
// bytes each, with no DER (RFC 6605 section 4, RFC 7518 section 3.4).
// Returns 1 for a valid signature and 0 for anything else.
int p256_ecdsa_verify_raw(const uint8_t pub[64], const uint8_t msg_hash[32], const uint8_t sig[64]);
#endif

#endif
