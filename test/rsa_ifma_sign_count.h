// The calls a test binary counts into rsa_ifma_sign.c's
// rsa_ifma_sign_power_pair and rsa_ifma_sign_wipe_below, and into
// avx512_wipe.c's avx512_wipe_registers, which rsa_sign64.c makes on
// x86-64 for a session whose ch_cfg.cpu holds CH_CPU_AVX512_IFMA and
// CH_CPU_CONSTANT_TIME_MULTIPLY (docs/decisions.md 120).
// test/rsa_ifma_sign_count.c defines the three as counts, the first on
// rsa_sign64.c's window, and a binary links that file in place of
// rsa_ifma_sign.c and avx512_wipe.c. bin/x86_kernels_test links it, and so
// does every binary the Makefile's widemul_counted builds, through
// WIDEMUL_COUNT_UNITS.
//
// The names are these tests' alone, as test/rsa_ifma_count.h's are.
#ifndef CH_TEST_RSA_IFMA_SIGN_COUNT_H
#define CH_TEST_RSA_IFMA_SIGN_COUNT_H

// Calls to each. On arm64 rsa_sign64.c calls none, and the counts stay 0.
extern unsigned long rsa_ifma_sign_pair_calls;
extern unsigned long rsa_ifma_sign_wipe_calls;
extern unsigned long avx512_wipe_calls;

#endif
