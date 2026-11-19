/*
 * A probe of the CPU for a host program to copy: cpu_probe_value() returns a ch_cfg.cpu value
 * that a session on the calling thread can state, on Linux and macOS, on arm64 and x86-64
 * (docs/usage.md, "The CPU"). chapulin probes nothing, so its callers answer for it. This file is
 * an example and not part of the library, and no library source includes it.
 *
 * What it states:
 *
 *   - CH_CPU_PROBED, always.
 *   - On arm64, it sets PSTATE.DIT on the calling thread where the CPU has FEAT_DIT. Only then
 *     does it state a CH_CPU_CONSTANT_TIME_* bit, for each set of instructions the system reports:
 *     AES with PMULL, the multiply, SHA-256, SHA-512 and SHA-3. DIT is a state of one thread, so
 *     call it on each thread that runs a session.
 *   - On an Arm Neoverse N2 (implementer 0x41, part 0xd49), it leaves CH_CPU_CONSTANT_TIME_SHA3
 *     clear. There the SHA-3 instructions run Keccak 1.8 times slower than the portable code, and
 *     the bit gains AES-GCM's EOR3 passes 2% (docs/decisions.md 240).
 *   - On x86-64, the bits for the kernels that the CPU and the operating system report: AVX2, VAES,
 *     AVX-512, AVX-512 IFMA, BMI1, and BMI2 with ADX. A CH_CPU_CONSTANT_TIME_* bit also needs
 *     DOITM, which only the operating system sets, so it states those bits only in a build with
 *     -DCPU_PROBE_DOITM_IS_SET, for a program that knows its system sets DOITM.
 *
 * Build it beside your program, with your build's -DCH_CPU_RUNTIME:
 *
 *     cc -O2 -DCH_CPU_RUNTIME -Iinclude -o cpu_probe examples/cpu_probe.c
 *
 * and set cfg.cpu = cpu_probe_value() on the thread that runs the session.
 */
#include <stdint.h>
#include <stdio.h>

#include <chapulin/cpu_cfg.h>

#ifndef CH_CPU_RUNTIME
#error "ch_cfg.cpu exists in a host object alone: build this file with -DCH_CPU_RUNTIME"
#endif

#ifdef __x86_64__
#include <cpuid.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#else
#include <stdlib.h>
#include <sys/auxv.h>
#endif

#ifdef __aarch64__

#ifdef __APPLE__
// Whether the Mac's kernel reports a feature, such as hw.optional.arm.FEAT_SHA3.
static int reports(const char *name) {
    int value = 0;
    size_t value_len = sizeof value;
    return sysctlbyname(name, &value, &value_len, NULL, 0) == 0 && value == 1;
}

#define HAS_DIT() reports("hw.optional.arm.FEAT_DIT")
#define HAS_AES_PMULL()                                                                            \
    (reports("hw.optional.arm.FEAT_AES") && reports("hw.optional.arm.FEAT_PMULL"))
#define HAS_SHA256() reports("hw.optional.arm.FEAT_SHA256")
#define HAS_SHA512() reports("hw.optional.arm.FEAT_SHA512")
#define HAS_SHA3() reports("hw.optional.arm.FEAT_SHA3")
static int is_neoverse_n2(void) {
    return 0;
}
#else
// Linux's auxiliary vector: arm64 code outside the kernel cannot read the ID registers itself.
#ifndef HWCAP_DIT
#define HWCAP_DIT (1UL << 24)
#endif
#define HAS_DIT() ((getauxval(AT_HWCAP) & HWCAP_DIT) != 0)
#define HAS_AES_PMULL()                                                                            \
    ((getauxval(AT_HWCAP) & (HWCAP_AES | HWCAP_PMULL)) == (HWCAP_AES | HWCAP_PMULL))
#define HAS_SHA256() ((getauxval(AT_HWCAP) & HWCAP_SHA2) != 0)
#define HAS_SHA512() ((getauxval(AT_HWCAP) & HWCAP_SHA512) != 0)
#define HAS_SHA3() ((getauxval(AT_HWCAP) & HWCAP_SHA3) != 0)

// Whether cpu0 is an Arm Neoverse N2, from its MIDR_EL1, which Linux publishes in sysfs:
// implementer in bits 31 to 24, part number in bits 15 to 4.
static int is_neoverse_n2(void) {
    FILE *f = fopen("/sys/devices/system/cpu/cpu0/regs/identification/midr_el1", "r");
    unsigned long midr = 0;
    int parsed = f != NULL && fscanf(f, "%lx", &midr) == 1;
    if (f != NULL) {
        fclose(f);
    }
    return parsed && ((midr >> 24) & 0xffUL) == 0x41UL && ((midr >> 4) & 0xfffUL) == 0xd49UL;
}
#endif

// Sets PSTATE.DIT on this thread, and reads it back. The MSR that writes 1 to DIT is written as its
// encoding, so the file builds with no -march flag.
static int set_dit(void) {
    uint64_t dit;
    __asm__ volatile(".inst 0xd503415f" ::: "memory");
    __asm__ volatile("mrs %0, s3_3_c4_c2_5" : "=r"(dit));
    return ((dit >> 24) & 1U) != 0;
}

static uint32_t cpu_probe_value(void) {
    uint32_t value = CH_CPU_PROBED;
    if (!HAS_DIT() || !set_dit()) {
        return value;
    }
    value |= CH_CPU_CONSTANT_TIME_MULTIPLY;
    if (HAS_AES_PMULL()) {
        value |= CH_CPU_CONSTANT_TIME_AES;
    }
    if (HAS_SHA256()) {
        value |= CH_CPU_CONSTANT_TIME_SHA256;
    }
    if (HAS_SHA512()) {
        value |= CH_CPU_CONSTANT_TIME_SHA512;
    }
    if (HAS_SHA3() && !is_neoverse_n2()) {
        value |= CH_CPU_CONSTANT_TIME_SHA3;
    }
    return value;
}

#else // __x86_64__

// CPUID leaf 7, subleaf 0: EBX and ECX.
static void leaf7(unsigned int *ebx, unsigned int *ecx) {
    unsigned int eax = 0;
    unsigned int edx = 0;
    *ebx = 0;
    *ecx = 0;
    if (!__get_cpuid_count(7, 0, &eax, ebx, ecx, &edx)) {
        *ebx = 0;
        *ecx = 0;
    }
}

static uint32_t cpu_probe_value(void) {
    uint32_t value = CH_CPU_PROBED;
    unsigned int ebx = 0;
    unsigned int ecx = 0;
    __builtin_cpu_init();
    leaf7(&ebx, &ecx);
    // __builtin_cpu_supports reports AVX2 and AVX-512 only where the system saves their registers.
    int avx2 = __builtin_cpu_supports("avx2") != 0;
    int aes_pclmul = __builtin_cpu_supports("aes") && __builtin_cpu_supports("pclmul");
    if (avx2) {
        value |= CH_CPU_AVX2;
    }
    if (aes_pclmul && avx2 && ((ecx >> 9) & 1U) && ((ecx >> 10) & 1U)) {
        value |= CH_CPU_VAES;
        if (__builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512bw") &&
            __builtin_cpu_supports("avx512vl")) {
            value |= CH_CPU_AVX512;
        }
    }
    if (__builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512ifma")) {
        value |= CH_CPU_AVX512_IFMA;
    }
    if (((ebx >> 8) & 1U) && ((ebx >> 19) & 1U)) {
        value |= CH_CPU_BMI2_ADX;
    }
    if ((ebx >> 3) & 1U) {
        value |= CH_CPU_BMI1;
    }
#ifdef CPU_PROBE_DOITM_IS_SET
    value |= CH_CPU_CONSTANT_TIME_MULTIPLY;
    if (aes_pclmul) {
        value |= CH_CPU_CONSTANT_TIME_AES;
    }
    if (((ebx >> 29) & 1U) && __builtin_cpu_supports("ssse3") && __builtin_cpu_supports("sse4.1")) {
        value |= CH_CPU_CONSTANT_TIME_SHA256;
    }
#endif
    return value;
}

#endif

int main(void) {
    uint32_t value = cpu_probe_value();
    printf("ch_cfg.cpu 0x%x\n", (unsigned)value);
    return (value & ~(uint32_t)CH_CPU_DEFINED) != 0;
}
