// Test code only: whether the CPU that runs a host test binary has the hash
// instructions its ch_cfg.cpu bits name (cpu_cfg.h, docs/decisions.md 93).
// The library asks no CPU anything, and its callers answer for it; a test
// may ask. A host object targets x86-64 or arm64 (cpu_cfg.h), and its test
// binaries run on macOS and Linux: x86-64 answers from CPUID, an arm64 Mac
// from sysctl, and any other arm64 system from Linux's auxiliary vector,
// because arm64 code outside the kernel cannot read the ID registers
// itself. No other binary has a ch_cfg.cpu, and this header declares
// nothing for one.
//
// A binary whose CPU lacks the instructions a row names skips that row and
// says so, unless CH_REQUIRE_HASH_INSTRUCTIONS is 1 in its environment: then
// it fails. test/aes-runtime-qemu.sh sets it for the CPU models that have
// the instructions, so a qemu that lacks them fails a row and does not skip
// it.
#ifndef CH_TEST_HASH_INSTRUCTIONS_CPU_H
#define CH_TEST_HASH_INSTRUCTIONS_CPU_H

#include "cpu_cfg.h"

#ifdef CH_CPU_RUNTIME
#include <stdlib.h>
#include <string.h>

#ifdef __x86_64__
#include <cpuid.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#else
#include <sys/auxv.h>
#endif

#if !defined(__x86_64__) && defined(__APPLE__)
// Whether the Mac's kernel reports the feature name names, such as
// hw.optional.arm.FEAT_SHA256.
static inline int apple_cpu_reports(const char *name) {
    int value = 0;
    size_t value_len = sizeof value;
    return sysctlbyname(name, &value, &value_len, NULL, 0) == 0 && value == 1;
}
#endif

// What CH_CPU_CONSTANT_TIME_SHA256 names: on arm64 FEAT_SHA256, and on
// x86-64 the SHA extensions, which CPUID leaf 7 reports in bit 29 of EBX,
// with SSSE3 and SSE4.1.
static inline int cpu_has_sha256_instructions(void) {
#ifdef __x86_64__
    __builtin_cpu_init();
    if (!__builtin_cpu_supports("ssse3") || !__builtin_cpu_supports("sse4.1")) {
        return 0;
    }
    unsigned int eax = 0;
    unsigned int ebx = 0;
    unsigned int ecx = 0;
    unsigned int edx = 0;
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return 0;
    }
    return ((ebx >> 29) & 1U) != 0;
#elif defined(__APPLE__)
    return apple_cpu_reports("hw.optional.arm.FEAT_SHA256");
#else
    return (getauxval(AT_HWCAP) & HWCAP_SHA2) != 0;
#endif
}

// Whether a binary whose CPU lacks a hash's instructions must fail rather
// than skip.
static inline int hash_instructions_required(void) {
    const char *required = getenv("CH_REQUIRE_HASH_INSTRUCTIONS");
    return required != NULL && strcmp(required, "1") == 0;
}
#endif // CH_CPU_RUNTIME

#endif
