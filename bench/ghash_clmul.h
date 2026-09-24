// A GHASH built on the carry-less multiply instruction. It is a prototype
// for measurement, written so bench/aead.sh can time it, and the library
// does not contain it: quic_gcm.c's bit-by-bit GHASH is the only one
// chapulin ships. bench/ghash_clmul.c states what the prototype does and
// what it leaves out.
#ifndef CH_BENCH_GHASH_CLMUL_H
#define CH_BENCH_GHASH_CLMUL_H

#include <stddef.h>
#include <stdint.h>

// The instruction the prototype uses, named only where the compiler
// targets it: PMULL is part of the Armv8 AES extension, so
// __ARM_FEATURE_AES implies it, and x86-64 needs -mpclmul for
// __PCLMUL__. Where neither is defined the prototype does not exist and
// bench/aead.c leaves its rows out.
#ifdef __ARM_FEATURE_AES
#define GHASH_CLMUL_INSTRUCTION "PMULL"
#elif defined(__PCLMUL__)
#define GHASH_CLMUL_INSTRUCTION "PCLMULQDQ"
#endif

#define GHASH_CLMUL_BLOCK 16

#ifdef GHASH_CLMUL_INSTRUCTION
// out = GHASH_H(A || pad || C || pad || [len(A)]64 || [len(C)]64), the
// function SP 800-38D §6.4 defines and quic_gcm.c's gcm_ghash computes.
// It takes the hash subkey H itself rather than the AES key, so the
// caller runs the one forward-cipher block that derives H.
//
// Requires: subkey points at GHASH_CLMUL_BLOCK readable bytes; aad at
// aad_len readable bytes and ct at n readable bytes, either of which may
// be NULL when its length is 0; out at GHASH_CLMUL_BLOCK writable bytes.
void ghash_clmul(const uint8_t subkey[GHASH_CLMUL_BLOCK], const uint8_t *aad, size_t aad_len,
                 const uint8_t *ct, size_t n, uint8_t out[GHASH_CLMUL_BLOCK]);
#endif

#endif
