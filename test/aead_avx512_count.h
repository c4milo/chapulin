// The calls a counting binary counts into chacha20_avx512.c's
// chacha20_avx512_xor, which chacha20.c's chacha20_xor_cpu makes on x86-64
// for a session whose ch_cfg.cpu holds CH_CPU_AVX512_IFMA
// (docs/decisions.md 121). test/aead_avx512_count.c defines that entry as
// a count and a call to chacha20_vector_xor, which writes the bytes the
// kernel writes under the same contract. It also defines
// poly1305_ifma_blocks_native_counted, the name
// test/widemul_runtime_count.c's poly1305_ifma_blocks_native counts and
// calls, as a call to poly1305_vector_blocks_native_counted, which leaves
// the accumulator the AVX-512 IFMA Poly1305 leaves under the same
// contract. Every binary that links WIDEMUL_COUNT_UNITS, the Makefile's
// widemul_counted builds and bin/widemul_runtime_test, links that file in
// place of chacha20_avx512.c and of poly1305_ifma.c's native copy. So the
// library's sources run unchanged, no AVX-512 instruction runs, and the
// binary reads which calls the library sent to either kernel, on any
// x86-64 CPU, as test/rsa_ifma_count.h's count does for RSA's public
// operation. bin/x86_kernels_test counts both kernels' calls through
// test/x86_kernels_count.c instead.
//
// The name is these tests' alone, as test/rsa_ifma_count.h's is.
#ifndef CH_TEST_AEAD_AVX512_COUNT_H
#define CH_TEST_AEAD_AVX512_COUNT_H

#include <stddef.h>
#include <stdint.h>

#include "poly1305.h"

// Calls to chacha20_avx512_xor. On arm64 chacha20_xor_cpu calls none, and
// the count stays 0.
extern unsigned long chacha20_avx512_calls;

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)
// The name test/widemul_runtime_count.c's poly1305_ifma_blocks_native
// calls: poly1305_ifma_blocks's contract, on the 128-bit path.
void poly1305_ifma_blocks_native_counted(poly1305 *p, const uint8_t *m, size_t n);
#endif

#endif
