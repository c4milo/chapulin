// The calls a test binary counts into rsa_mont64_adx.c's multiplication and
// square, which rsa_sign64.c makes on x86-64 for a session whose ch_cfg.cpu
// holds CH_CPU_BMI2_ADX and CH_CPU_CONSTANT_TIME_MULTIPLY and not the IFMA
// path's bits (docs/decisions.md 183). test/rsa_mont64_adx_count.c defines
// the two as counts over rsa_mont64.c's, and a binary links that file in
// place of rsa_mont64_adx.c. bin/x86_kernels_test links it, and so does
// every binary the Makefile's widemul_counted builds, through
// WIDEMUL_COUNT_UNITS.
//
// The names are these tests' alone, as test/rsa_ifma_count.h's are.
#ifndef CH_TEST_RSA_MONT64_ADX_COUNT_H
#define CH_TEST_RSA_MONT64_ADX_COUNT_H

// Calls to the two. On arm64 rsa_sign64.c calls neither, and the count stays 0.
extern unsigned long rsa_mont64_adx_calls;

#endif
