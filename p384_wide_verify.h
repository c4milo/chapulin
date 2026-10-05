// ECDSA P-384 verification on p384_wide_field.c's six 64-bit limbs, which
// a host object holds (-DCH_CPU_RUNTIME, cpu_cfg.h; docs/decisions.md 97).
// A device object holds none of it and verifies on p384.c's 32-bit limbs,
// which stay the reference bin/p384_equiv_test compares this file with.
//
// Its one caller is p384_ecdsa_verify (p384.c), in every session of a
// host object: a key, a hash and a signature are public, so no session
// needs to state a multiply's timing first.
#ifndef CH_P384_WIDE_VERIFY_H
#define CH_P384_WIDE_VERIFY_H

#include <stdint.h>

#include "p384.h"

#ifdef CH_CPU_RUNTIME

// Returns 1 when (r, s) is a valid signature of msg_hash under pub, and 0
// for anything else: a scalar outside [1, n - 1], a key coordinate at or
// above p, a key off the curve, or a signature that does not verify. pub
// is the raw uncompressed point (X||Y), and r_be and s_be are the two
// scalars as 48 big-endian bytes each, which p384.c's strict-DER reader
// writes. The verdict is p384.c's for every input.
int p384_wide_verify_rs(const uint8_t pub[P384_PUB_LEN], const uint8_t msg_hash[P384_LEN],
                        const uint8_t r_be[P384_LEN], const uint8_t s_be[P384_LEN]);

#endif // CH_CPU_RUNTIME

#endif
