// The wide P-256 scalar arithmetic: the two routines of p256_scalar.h that multiply, modulo the
// group order n, on four 64-bit words and the 64x64->128 multiply ct.h names ct_mul128. A host
// object (-DCH_CPU_RUNTIME, cpu_cfg.h) holds it beside p256_scalar.c's eight 32-bit words, and
// widemul.h runs it for a session whose ch_cfg.cpu holds CH_CPU_CONSTANT_TIME_MULTIPLY
// (docs/decisions.md 89 and 94). A session without the bit runs p256_scalar.c on ct.h's 16x16
// decomposition, and a device object holds that file alone.
//
// Both routines take and leave p256_scalar.h's scalar, eight 32-bit words, and keep the 64-bit
// words inside the call. The routines of p256_scalar.h that multiply nothing, the marshalling,
// the predicates, p256_scalar_cmov, p256_scalar_reduce and p256_scalar_add, have no second
// copy: every session calls p256_scalar.c's.
//
// The contract is p256_scalar.h's: no branch and no memory index reads a word, and every
// choice is a mask. The values here are the ECDSA private key and the signing nonce, so each
// call wipes the words it copied and every value it computed before it returns.
#ifndef CH_P256_WIDE_SCALAR_H
#define CH_P256_WIDE_SCALAR_H

#include "p256_scalar.h"

#ifdef CH_CPU_RUNTIME

// o = a*b mod n, for scalars below n. p256_scalar_mul on 64-bit words.
void p256_wide_scalar_mul(p256_scalar *o, const p256_scalar *a, const p256_scalar *b);

// o = a^-1 mod n, and 0 for a = 0. p256_wide_inverse.h's binary GCD computes it, where
// p256_scalar_inverse raises a to n - 2 (docs/decisions.md 115).
void p256_wide_scalar_inverse(p256_scalar *o, const p256_scalar *a);

// The same scalar for an a the caller states is public, by p256_wide_inverse_public, whose time
// depends on a. p256_wide_verify.c inverts a signature's s with it (docs/decisions.md 116).
void p256_wide_scalar_inverse_public(p256_scalar *o, const p256_scalar *a);

#endif // CH_CPU_RUNTIME

#endif
