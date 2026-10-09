// Test code only: whether the CPU that runs a test binary has the
// instructions chapulin's x86-64 kernels run, read with the compiler's
// __builtin_cpu_supports and, for VAES and VPCLMULQDQ, which older
// compilers do not name there, with CPUID itself. The library asks no CPU
// anything, and its callers answer for it (docs/decisions.md 90); a test
// may ask. On any other architecture every answer is 0.
//
// A binary whose CPU lacks a kernel's instructions skips that kernel's
// cases and says so, unless CH_REQUIRE_X86_KERNELS is 1 in its
// environment, which CI's x86-64 kernel job sets: then it fails, because
// that job's runner must run the kernels. AVX-512 IFMA, which
// CH_CPU_AVX512_IFMA names, has a variable of its own,
// CH_REQUIRE_AVX512_IFMA, because some of that job's runners, such as an
// AMD EPYC 7763, lack it.
#ifndef CH_TEST_X86_KERNELS_CPU_H
#define CH_TEST_X86_KERNELS_CPU_H

#include <stdlib.h>
#include <string.h>

#ifdef __x86_64__
#include <cpuid.h>
#endif

// AVX2, which chacha20_avx2.c runs. __builtin_cpu_supports also reads
// whether the operating system saves the 256-bit registers.
static inline int x86_cpu_has_avx2(void) {
#ifdef __x86_64__
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx2") != 0;
#else
    return 0;
#endif
}

// What gcm_vaes.c runs: AES-NI and PCLMULQDQ, which the 128-bit steps it
// shares with gcm_hw.c run, AVX2, and VAES and VPCLMULQDQ, which CPUID
// leaf 7 reports in bits 9 and 10 of ECX.
static inline int x86_cpu_has_vaes(void) {
#ifdef __x86_64__
    __builtin_cpu_init();
    if (!__builtin_cpu_supports("aes") || !__builtin_cpu_supports("pclmul") ||
        !__builtin_cpu_supports("avx2")) {
        return 0;
    }
    unsigned int eax = 0;
    unsigned int ebx = 0;
    unsigned int ecx = 0;
    unsigned int edx = 0;
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return 0;
    }
    return ((ecx >> 9) & 1U) != 0 && ((ecx >> 10) & 1U) != 0;
#else
    return 0;
#endif
}

// AVX-512F and AVX-512 IFMA, which CH_CPU_AVX512_IFMA names (cpu_cfg.h).
// __builtin_cpu_supports also reads whether the operating system saves
// the opmask registers and the 512-bit registers. A CPU can have AVX-512F
// without IFMA, so the probe asks for IFMA by name.
static inline int x86_cpu_has_avx512_ifma(void) {
#ifdef __x86_64__
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx512f") != 0 && __builtin_cpu_supports("avx512ifma") != 0;
#else
    return 0;
#endif
}

// Whether a binary whose CPU lacks a kernel's instructions must fail
// rather than skip.
static inline int x86_kernels_required(void) {
    const char *required = getenv("CH_REQUIRE_X86_KERNELS");
    return required != NULL && strcmp(required, "1") == 0;
}

// Whether a binary whose CPU lacks AVX-512 IFMA must fail rather than
// skip.
static inline int x86_ifma_required(void) {
    const char *required = getenv("CH_REQUIRE_AVX512_IFMA");
    return required != NULL && strcmp(required, "1") == 0;
}

#endif
