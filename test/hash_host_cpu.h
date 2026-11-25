// Test code only: the bits this CPU has of what hash.h's calls run on
// (docs/decisions.md 246), as a ch_cfg.cpu value: the SHA-256
// instructions; on x86-64 AVX2, which SHA-384 and SHA-512 run on, and
// BMI1 with BMI2 and ADX, which SHA-3 and SHAKE run on; on arm64 the
// SHA-512 and SHA-3 instructions. The test states their timing, as every
// host test does for the bits it sets. bin/hash_test and the Wycheproof
// hash test run each vector under this value and under CH_CPU_PROBED.
#ifndef CH_TEST_HASH_HOST_CPU_H
#define CH_TEST_HASH_HOST_CPU_H

#include <stdint.h>

#include "cpu_cfg.h"
#include "hash_instructions_cpu.h"
#include "x86_kernels_cpu.h"

static inline uint32_t hash_host_cpu(void) {
    uint32_t cpu = CH_CPU_PROBED;
    if (cpu_has_sha256_instructions()) {
        cpu |= CH_CPU_CONSTANT_TIME_SHA256;
    }
#ifdef __x86_64__
    if (x86_cpu_has_avx2()) {
        cpu |= CH_CPU_AVX2;
    }
    if (x86_cpu_has_bmi1() && x86_cpu_has_bmi2_adx()) {
        cpu |= CH_CPU_BMI1 | CH_CPU_BMI2_ADX;
    }
#else
    if (cpu_has_sha512_instructions()) {
        cpu |= CH_CPU_CONSTANT_TIME_SHA512;
    }
    if (cpu_has_sha3_instructions()) {
        cpu |= CH_CPU_CONSTANT_TIME_SHA3;
    }
#endif
    return cpu;
}

#endif
