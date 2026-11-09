// The ChaCha20-Poly1305 seal and open of an x86-64 host object in one
// pass over the data, on chacha20_avx2.c's ChaCha20 pass and
// poly1305_wide.h's block step on three 64-bit limbs. Each pass of eight
// ChaCha20 blocks also absorbs 32 Poly1305 blocks, four after each of its
// first eight double rounds, so the vector units run the rounds while the
// scalar multiplier runs the blocks, and each byte is read from memory once
// for both (docs/decisions.md 199 and 206). The last bytes of a message run
// on poly1305_avx2.c's kernel. aead.c calls the two entries for a session
// whose ch_cfg.cpu holds CH_CPU_AVX2 and CH_CPU_CONSTANT_TIME_MULTIPLY and
// not CH_CPU_AVX512_IFMA. The two-pass AEAD stays the reference:
// bin/aead_avx2_equiv_test compares the entries with it on a CPU that has
// AVX2.
//
// The file holds widening multiplies, ct_mul128's 64x64->128 products and
// poly1305_avx2.c's VPMULUDQ, so it compiles as a native copy alone
// (widemul_native.h), and the caller's CH_CPU_CONSTANT_TIME_MULTIPLY covers
// them, as it covers x25519_wide.c's and poly1305_avx2.c's. Every other
// instruction is an add, a carry, a shift by a constant, a mask or a lane
// move, with no branch on the key, r, the accumulator or the data, and no
// address computed from them. Only the byte count n decides how many
// passes run, and it is public.
#ifndef CH_AEAD_AVX2_H
#define CH_AEAD_AVX2_H

#include <stddef.h>
#include <stdint.h>

#include "chacha20.h"
#include "poly1305.h"

// The entries exist in an x86-64 host object whose Poly1305 runs on the
// native multiply. CH_CT_WIDEMUL, which forces the 16x16 decomposition,
// removes them, as it removes poly1305_avx2.c's kernel.
#if defined(CH_CPU_RUNTIME) && defined(__x86_64__) && !defined(CH_CT_WIDEMUL)
#define CH_AEAD_AVX2 1
#endif

#ifdef CH_AEAD_AVX2

// The two entries run one pass over n bytes from AEAD_AVX2_MIN up. Below it
// a message has fewer than two ChaCha20 passes, and aead.c runs two passes
// over it.
#define AEAD_AVX2_MIN ((size_t)1024)

// ct = pt XOR the keystream of key and nonce from block counter 1, and the
// n bytes of ct absorbed into p, as poly1305_update_avx2_native absorbs
// them. p holds the Poly1305 key, the associated data and its padding, so
// p->fill is 0. pt == ct is allowed, as is ct below pt (ct <= pt), under
// chacha20_xor's contract. n is AEAD_AVX2_MIN or more. Before it returns
// it wipes the powers of r and writes zero to ymm0 to ymm15.
//
// Requires: a CPU with AVX2.
void aead_avx2_seal(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                    poly1305 *p, const uint8_t *pt, size_t n, uint8_t *ct);

// The n bytes of ct absorbed into p, as aead_avx2_seal absorbs them, and pt
// = ct XOR the same keystream. Each byte of ct is absorbed before the byte
// at its address is written, so pt == ct is allowed, as is pt below ct
// (pt <= ct). The caller compares the tag after the call, and wipes pt on
// a mismatch. The other terms are aead_avx2_seal's.
//
// Requires: a CPU with AVX2.
void aead_avx2_open(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                    poly1305 *p, const uint8_t *ct, size_t n, uint8_t *pt);

#endif // CH_AEAD_AVX2

#endif
