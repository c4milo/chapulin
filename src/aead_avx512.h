// The ChaCha20-Poly1305 seal and open of an x86-64 host object in one
// pass over the data on AVX-512: chacha20_avx512.c's pass of sixteen
// ChaCha20 blocks, and between its double rounds four groups of sixteen
// Poly1305 blocks in poly1305_ifma.c's eight IFMA lanes, so each byte is
// read once from memory for both (docs/decisions.md 226). The two kernels'
// texts are chacha20_avx512_lanes.h and poly1305_ifma_group.h, which the
// kernels include too. aead.c calls the two entries for a session whose
// ch_cfg.cpu holds CH_CPU_AVX512_IFMA and CH_CPU_CONSTANT_TIME_MULTIPLY,
// from AEAD_AVX512_MIN bytes up. The two-pass AEAD stays the reference:
// bin/aead_avx512_equiv_test compares the entries with it on a CPU that has
// AVX-512 IFMA, and the entries' own text over the two lane models on every
// machine.
//
// The file holds widening multiplies, AVX-512 IFMA's 52-bit products, so it
// compiles as a native copy alone (widemul_native.h), and the caller's
// CH_CPU_CONSTANT_TIME_MULTIPLY covers them, as it covers poly1305_ifma.c's
// (docs/decisions.md 121). Every other instruction is an add, an
// exclusive-or, a rotation or a shift by a constant, a mask or a lane move
// under a constant order, with no branch on the key, r, the accumulator or
// the data, and no address computed from them. Only the byte count n
// decides how many passes run, and it is public. The key, the keystream and
// the powers of r pass through 512-bit registers, which no C statement can
// name, so each entry calls avx512_wipe_registers before it returns.
#ifndef CH_AEAD_AVX512_H
#define CH_AEAD_AVX512_H

#include <stddef.h>
#include <stdint.h>

#include "chacha20.h"
#include "poly1305.h"

// The entries exist in an x86-64 host object whose Poly1305 runs on the
// native multiply. CH_CT_WIDEMUL, which forces the 16x16 decomposition,
// removes them, as it removes poly1305_ifma.c's kernel. A test unit that
// defines CH_AEAD_AVX512_MODEL defines them on any host: aead_avx512.c then
// compiles over test/chacha20_avx512_model_lanes.h and
// test/poly1305_ifma_model_lanes.h, the models of each instruction in
// portable C. No library build names that define.
#if (defined(CH_CPU_RUNTIME) && defined(__x86_64__) && !defined(CH_CT_WIDEMUL)) ||                 \
    defined(CH_AEAD_AVX512_MODEL)
#define CH_AEAD_AVX512 1
#endif

// The two entries run one pass over n bytes from AEAD_AVX512_MIN up. Below
// it a message has fewer than two passes of sixteen ChaCha20 blocks, so no
// pass absorbs a group, and aead.c runs two passes over it. The constant
// exists on every host, for the tests that compare the two.
#define AEAD_AVX512_MIN ((size_t)2048)

#ifdef CH_AEAD_AVX512

// ct = pt XOR the keystream of key and nonce from block counter 1, and the
// n bytes of ct absorbed into p, as poly1305_update_ifma_native absorbs
// them. p holds the Poly1305 key, the associated data and its padding, so
// p->fill is 0. pt == ct is allowed, as is ct below pt (ct <= pt), under
// chacha20_xor's contract. n is AEAD_AVX512_MIN or more. Before it returns
// it wipes the powers of r and its input words, and calls
// avx512_wipe_registers.
//
// Requires: a CPU with AVX-512F and AVX-512 IFMA whose operating system
// saves the 512-bit and mask registers.
void aead_avx512_seal(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                      poly1305 *p, const uint8_t *pt, size_t n, uint8_t *ct);

// The n bytes of ct absorbed into p, as aead_avx512_seal absorbs them, and
// pt = ct XOR the same keystream. Each byte of ct is absorbed before the
// byte at its address is written, so pt == ct is allowed, as is pt below ct
// (pt <= ct). The caller compares the tag after the call, and wipes pt on
// a mismatch. The other terms are aead_avx512_seal's.
//
// Requires: a CPU with AVX-512F and AVX-512 IFMA whose operating system
// saves the 512-bit and mask registers.
void aead_avx512_open(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                      poly1305 *p, const uint8_t *ct, size_t n, uint8_t *pt);

#endif // CH_AEAD_AVX512

#endif
