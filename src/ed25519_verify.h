// Ed25519 signature verification (RFC 8032 section 5.1.7), for DNSSEC
// algorithm 15 (RFC 8080) under CH_DNSSEC
// (https://github.com/c4milo/chapulin/issues/189), and for a JWS under
// EdDSA (RFC 8037) under CH_JWS. It verifies only, over
// a key, a signature and a hash that are all public, so it is variable
// time. Its body is x25519_wide_ed25519.h, which x25519_wide.c includes,
// because it runs on that file's radix-2^51 field and its Edwards points.
#ifndef CH_ED25519_VERIFY_H
#define CH_ED25519_VERIFY_H

#include <stdint.h>

#if (defined(CH_DNSSEC) || defined(CH_JWS)) && defined(CH_CPU_RUNTIME)
// Returns 1 when sig, R then S, 32 bytes each, is a valid Ed25519
// signature under key, the 32-byte encoding of A, and hram is the 64-byte
// SHA-512 of R, A and the message, in that order. Returns 0 for anything
// else. The rule is RFC 8032's cofactorless equation [S]B = R + [h]A, where
// h is hram mod L, and it refuses as libsodium does: an S at or above L, an
// encoding of A or R whose y is not below p or that names no point, and an
// A of small order. It also refuses an A outside the subgroup of prime
// order L, which libsodium takes: every key [a]B is in that subgroup, so
// only a key made to be outside it is refused (docs/decisions.md 227). R
// is refused by the comparison itself: the call compares R's bytes with
// the canonical encoding of [S]B - [h]A.
int ed25519_verify_hram(const uint8_t key[32], const uint8_t hram[64], const uint8_t sig[64]);
#endif

#endif
