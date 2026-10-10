// A host object's AVX-512 ChaCha20 kernel on x86-64: the stream cipher of
// RFC 8439 §2.4, sixteen blocks a pass in 512-bit vectors, each vector
// holding one word of the sixteen blocks. It is chacha20_avx2.c with
// sixteen lanes in place of eight and VPROLD for every rotation, and
// AVX-512's 32 vector registers hold one pass's 16 words beside their 16
// input words. Every x86-64 host object carries it beside chacha20_avx2.c's
// kernel and chacha20_vector.c's SSE2 path, and chacha20.c's
// chacha20_xor_cpu runs it where the session's ch_cfg.cpu holds
// CH_CPU_AVX512_IFMA, which says the CPU has AVX-512F and its operating
// system saves the 512-bit and mask registers. chacha20.c's loop stays the
// reference: bin/chacha20_equiv_test compares the kernel with it over the
// same inputs on a CPU that has AVX-512F.
//
// Every function in chacha20_avx512.c carries the target attribute that
// turns AVX-512F on for that function alone, as chacha20_avx2.c's carry
// AVX2, so the object needs no compiler flag and the rest of it runs on any
// x86-64 CPU. chapulin probes no CPU: the caller's bit decides whether the
// kernel runs.
//
// It is constant time by the construction chacha20.c keeps: adds, XORs,
// rotations by constant counts and lane moves under constant orders, each
// on every lane, with no table, no multiply, no branch on the key, the
// nonce, the counter or the data, and no address computed from any of
// them. Only the byte count n decides how many blocks run, and n is
// public. The kernel ran the key through 512-bit registers, which no C
// statement can name, so it calls avx512_wipe_registers before it returns
// (avx512_wipe.h, docs/decisions.md 121).
#ifndef CH_CHACHA20_AVX512_H
#define CH_CHACHA20_AVX512_H

#include <stddef.h>
#include <stdint.h>

#include "chacha20.h"

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

// chacha20_xor's contract, computed sixteen blocks a pass: out = in XOR
// keystream(key, nonce, counter...), with the 32-bit block counter counter
// for the first block and one more, modulo 2^32, for each block after it.
// out == in is allowed, as is out below in (out <= in): each 64 bytes are
// read before the 64 bytes at the same offset are written, in ascending
// order, so each address is written only after it was last read.
//
// Every pass but the last is sixteen blocks. A message whose last 1 to 256
// bytes fall past its whole passes ends on a pass of four blocks, which
// runs in the same loop as the last pass of sixteen where there is one. Any
// other message ends on a pass of sixteen.
//
// Requires: a CPU with AVX-512F whose operating system saves the 512-bit
// and mask registers. chacha20_xor_cpu decides that from the session's
// CH_CPU_AVX512_IFMA bit; on a CPU without them the first instruction
// faults.
void chacha20_avx512_xor(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                         uint32_t counter, const uint8_t *in, uint8_t *out, size_t n);

#endif // CH_CPU_RUNTIME && __x86_64__

#endif
