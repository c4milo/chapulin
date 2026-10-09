// The calls a test binary counts into rsa_ifma.c's rsa_ifma_public, RSA's
// public operation on AVX-512 IFMA (rsa_ifma.h), which rsa_mont.c's
// rsa_vp1_cpu makes on x86-64 for a session whose ch_cfg.cpu holds
// CH_CPU_AVX512_IFMA. test/rsa_ifma_count.c defines rsa_ifma_public as a
// count and the bytes rsa_mont64_public writes, and a binary links that
// file in place of rsa_ifma.c. So the library's sources run unchanged, no
// AVX-512 instruction runs, and the binary reads which calls the library
// sent to the kernel, on any x86-64 CPU. bin/x86_kernels_test links it,
// and so does every binary the Makefile's widemul_counted builds: the
// host loop and session binaries and bin/webpki_auth_host, which count
// the calls each caller of the two RSA verifiers makes over a handshake.
//
// The name is these tests' alone, as test/aes_runtime_count.h's are.
#ifndef CH_TEST_RSA_IFMA_COUNT_H
#define CH_TEST_RSA_IFMA_COUNT_H

// Calls to rsa_ifma_public. On arm64 rsa_ifma.h declares no such entry,
// rsa_vp1_cpu calls none, and the count stays 0.
extern unsigned long rsa_ifma_public_calls;

#endif
