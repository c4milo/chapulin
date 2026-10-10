// The calls a test binary counts into rsa_avx2.c's rsa_avx2_public, RSA's
// public operation on AVX2 (rsa_avx2.h), which rsa_mont.c's rsa_vp1_cpu
// makes on x86-64 for a session whose ch_cfg.cpu holds CH_CPU_AVX2 and not
// CH_CPU_AVX512_IFMA. test/rsa_avx2_count.c defines rsa_avx2_public as a
// count and the bytes rsa_mont64_public writes, and bin/x86_kernels_test
// links that file in place of rsa_avx2.c. So the library's sources run
// unchanged, no AVX2 instruction of the kernel runs, and the binary reads
// which calls the library sent to the kernel, on any x86-64 CPU.
//
// The name is these tests' alone, as test/rsa_ifma_count.h's is.
#ifndef CH_TEST_RSA_AVX2_COUNT_H
#define CH_TEST_RSA_AVX2_COUNT_H

// Calls to rsa_avx2_public. On arm64 rsa_avx2.h declares no such entry,
// rsa_vp1_cpu calls none, and the count stays 0.
extern unsigned long rsa_avx2_public_calls;

#endif
