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
// docs/webpki.md under "Bounds". rsa_mont.c sizes its word arrays from
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
//
// A device object computes it on 32-bit words and a host object
// (-DCH_CPU_RUNTIME) on rsa_mont64.c's 64-bit words, and the two write
// the same bytes for every odd n. For an even n, which is no RSA modulus,
// each writes n_len bytes that are no power of sig, and the two differ:
// Montgomery arithmetic needs the inverse of n's low word, which an even
// word does not have.
void rsa_vp1(const uint8_t *n, size_t n_len, const uint8_t *sig, uint8_t *em);

#if defined(CH_CPU_RUNTIME) && !defined(__cplusplus)
#include "cpu_cfg.h"

// rsa_vp1 and rsa_pss_verify for one session of a host object: each takes
// the session's ch_cfg.cpu first, under the contract of the call it is
// named for, and gives that call's result for every input, an even n
// included. On x86-64, rsa_vp1_cpu hands the public operation to
// rsa_ifma.h's AVX-512 IFMA kernel where cpu holds CH_CPU_AVX512_IFMA and
// n is a modulus the kernel takes: at least RSA-2048, its top bit set, and
// odd. Every other input, and every input on arm64, takes rsa_vp1. The
// calls above, which take no value, run rsa_mont64.c in every session. A
// call holds no session, so a caller that holds one passes its value in
// an argument, as sha256.h's entries take it.
//
// Requires: what the plain call requires, and where cpu holds
// CH_CPU_AVX512_IFMA, a CPU with AVX-512F and AVX-512 IFMA whose operating
// system saves the 512-bit registers, which the session's caller states.
// On a CPU without them the first such instruction faults.
void rsa_vp1_cpu(uint32_t cpu, const uint8_t *n, size_t n_len, const uint8_t *sig, uint8_t *em);
int rsa_pss_verify_cpu(uint32_t cpu, const uint8_t *n, size_t n_len, const uint8_t msg_hash[32],
                       const uint8_t *sig, size_t sig_len);
#endif

// rsa_pss_verify as a source compiled into both objects calls it for a
// session, with its ch_cfg.cpu first, in hkdf.h's form. A host object
// passes the value to the entry above. A device object holds one public
// operation, so it calls rsa_pss_verify and never evaluates cpu: the
// expression may name a field that build does not declare.
#ifdef CH_CPU_RUNTIME
#define RSA_PSS_VERIFY_CPU(cpu, ...) rsa_pss_verify_cpu((cpu), __VA_ARGS__)
#else
#define RSA_PSS_VERIFY_CPU(cpu, ...) rsa_pss_verify(__VA_ARGS__)
#endif

#endif
