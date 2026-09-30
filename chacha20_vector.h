// CHACHA=vector: the ChaCha20 stream cipher of RFC 8439 §2.4, four blocks
// at a time in 128-bit vectors, NEON on arm64 and SSE2 on x86-64.
// chacha20.c's chacha20_xor calls it in place of its own loop when the
// build defines CH_CHACHA_VECTOR, and chacha20.c stays the reference:
// bin/chacha20_equiv_test compares the two over the same inputs.
//
// It is constant time by the construction chacha20.c keeps: adds, XORs and
// fixed rotations, each on every lane, with no table, no branch on the key,
// the nonce, the counter or the data, and no address computed from any of
// them. Only the byte count n decides how many blocks run, and n is public.
// docs/decisions.md 82 says why the path is a build axis.
#ifndef CH_CHACHA20_VECTOR_H
#define CH_CHACHA20_VECTOR_H

#include <stddef.h>
#include <stdint.h>

#include "chacha20.h"

// Everything below exists only in a build that defines CH_CHACHA_VECTOR,
// the way x25519_wide.h's field exists only under CH_X25519_WIDE.
#ifdef CH_CHACHA_VECTOR

// The compiler's own macros are the whole detection, and nothing probes a
// CPU at run time. Every AArch64 core has NEON and every x86-64 core has
// SSE2, so a compiler for either defines one of the two, and a compiler
// for any other target stops here rather than fall back to the portable
// loop without saying so. test/chacha-builds.sh checks that both rules
// fire.
#if !defined(__ARM_NEON) && !defined(__SSE2__)
#error "CHACHA=vector needs NEON or SSE2, and this compiler targets neither; build CHACHA=portable"
#endif
// A keystream word leaves its vector lane as the lane's four bytes in
// memory order, which is the little-endian order RFC 8439 §2.3 serializes
// in only on a little-endian target.
#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "CHACHA=vector needs a little-endian target; build CHACHA=portable"
#endif

// chacha20_xor's contract, computed four blocks at a time: out = in XOR
// keystream(key, nonce, counter...), with the 32-bit block counter
// counter for the first block and one more, modulo 2^32, for each block
// after it. out == in is allowed, as is out below in (out <= in): each 16
// bytes are read before the 16 bytes at the same offset are written, in
// ascending order, so each address is written only after it was last
// read.
void chacha20_vector_xor(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                         uint32_t counter, const uint8_t *in, uint8_t *out, size_t n);

#endif // CH_CHACHA_VECTOR

#endif
