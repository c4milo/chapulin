// Test code only: whether the CPU that runs a host test binary has SVE2, which CH_CPU_SVE2 names
// (cpu_cfg.h, docs/decisions.md 242). The library asks no CPU anything, and its callers answer
// for it; a test may ask. Linux reports SVE2 in its auxiliary vector, because arm64 code outside
// the kernel cannot read the ID registers itself. A Mac asks sysctl for hw.optional.arm.FEAT_SVE2,
// a name macOS 26 does not define, so a Mac answers no. An x86-64 object refuses the bit, and no
// x86-64 binary asks.
//
// A binary whose CPU lacks SVE2 skips a row under the bit and says so, unless CH_REQUIRE_SVE2 is
// 1 in its environment: then it fails. CI's arm64 job, on a Neoverse N2, sets it for the binaries
// that run the SVE2 copy, and so does test/aes-runtime-qemu.sh for the CPU models with SVE2.
#ifndef CH_TEST_SVE2_CPU_H
#define CH_TEST_SVE2_CPU_H

#include "cpu_cfg.h"

#if defined(CH_CPU_RUNTIME) && defined(__aarch64__)
#include <stdlib.h>
#include <string.h>

#ifdef __APPLE__
#include <sys/sysctl.h>
#else
#include <sys/auxv.h>
// Linux's bit for SVE2 in AT_HWCAP2, which an older libc's headers do not name.
#ifndef HWCAP2_SVE2
#define HWCAP2_SVE2 (1UL << 1)
#endif
#endif

static inline int cpu_has_sve2(void) {
#ifdef __APPLE__
    int value = 0;
    size_t value_len = sizeof value;
    return sysctlbyname("hw.optional.arm.FEAT_SVE2", &value, &value_len, NULL, 0) == 0 &&
           value == 1;
#else
    return (getauxval(AT_HWCAP2) & HWCAP2_SVE2) != 0;
#endif
}

// Whether a binary whose CPU lacks SVE2 must fail rather than skip.
static inline int sve2_required(void) {
    const char *required = getenv("CH_REQUIRE_SVE2");
    return required != NULL && strcmp(required, "1") == 0;
}
#endif // CH_CPU_RUNTIME && __aarch64__

#endif
