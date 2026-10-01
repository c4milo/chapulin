// CHACHA=vector's AVX2 kernel on x86-64: the ChaCha20 stream cipher of
// RFC 8439 §2.4, eight blocks a pass in 256-bit vectors, each vector
// holding one word of the eight blocks. Every x86-64 CHACHA=vector object
// carries it beside chacha20_vector.c's SSE2 path, and chacha20.c's
// chacha20_xor picks between the two at run time: the kernel runs where
// the CH_CPU_AVX2 bit of the caller's ch_cfg.cpu says the CPU has AVX2,
// and on no CPU until that field exists. chacha20.c stays the
// reference: bin/chacha20_equiv_test compares the kernel with it over the
// same inputs on a CPU that has AVX2.
//
// Every function in chacha20_avx2.c carries the target attribute that
// turns AVX2 on for that function alone, as aes_hw.c's functions carry
// the AES instructions under AES=runtime, so the object needs no compiler
// flag and the rest of it runs on any x86-64 CPU. chapulin probes no CPU:
// the caller's bit decides whether the kernel runs (docs/decisions.md 89
// and 90).
//
// It is constant time by the construction chacha20.c keeps: adds, XORs,
// shifts and byte shuffles, each on every lane, with no table, no branch
// on the key, the nonce, the counter or the data, and no address computed
// from any of them. The two byte shuffles take a constant order as their
// index, so the bytes they move depend on the order alone. Only the byte
// count n decides how many blocks run, and n is public.
#ifndef CH_CHACHA20_AVX2_H
#define CH_CHACHA20_AVX2_H

#include <stddef.h>
#include <stdint.h>

#include "chacha20.h"

#if defined(CH_CHACHA_VECTOR) && defined(__x86_64__)

// chacha20_xor's contract, computed a pass of eight blocks at a time: out
// = in XOR keystream(key, nonce, counter...), with the 32-bit block
// counter counter for the first block and one more, modulo 2^32, for each
// block after it. out == in is allowed, as is out below in (out <= in):
// each 32 bytes are read before the 32 bytes at the same offset are
// written, in ascending order, so each address is written only after it
// was last read.
//
// Requires: a CPU with AVX2. The caller decides that from its answer; on
// a CPU without AVX2 the first instruction faults.
void chacha20_avx2_xor(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                       uint32_t counter, const uint8_t *in, uint8_t *out, size_t n);

#endif // CH_CHACHA_VECTOR && __x86_64__

#endif
