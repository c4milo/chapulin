// ECDSA P-256 verification over the wide files: the check of one
// signature that p256_ecdsa_verify (p256.h) runs in a host object
// (-DCH_CPU_RUNTIME, cpu_cfg.h), in every session. p256.c reads the DER
// signature for both of its arms and hands r and s here; a device object
// holds p256.c's own 32-bit arithmetic and none of this file
// (docs/decisions.md 96 and 104).
//
// Every input is public: the peer's key, the hash and the signature all
// travel in the clear. So no bit of ch_cfg.cpu picks this path and no
// caller states the multiply's timing for it, as none does for RSA's
// public operation (rsa_mont64.h). The field and the scalar arithmetic
// are the wide files', which are constant time, and the points are
// p256_wide_verify_point.c's, which are variable time on purpose: a
// verifier's sum u1*G + u2*Q runs on Jacobian points in one pass over
// both scalars, and branches on its public values.
#ifndef CH_P256_WIDE_VERIFY_H
#define CH_P256_WIDE_VERIFY_H

#include <stdint.h>

#ifdef CH_CPU_RUNTIME

// Whether (r, s) is a signature of msg_hash under pub (FIPS 186-4 6.4.2):
// 1 when it is and 0 for anything else. pub is the raw uncompressed
// point, X||Y, and r and s are 32 big-endian bytes each, as p256.c's DER
// reader leaves them. It refuses r or s outside 1..n-1, a coordinate at
// or above p and a point off the curve. Not part of the public API.
int p256_wide_verify_rs(const uint8_t pub[64], const uint8_t msg_hash[32], const uint8_t r_be[32],
                        const uint8_t s_be[32]);

#endif // CH_CPU_RUNTIME

#endif
