// What a host test binary states about the CPU in ch_cfg.cpu (cpu_cfg.h, docs/decisions.md 89),
// and the values its rows try at every init call and ch_srv_check. A host binary compiles with
// -DCH_CPU_RUNTIME, as a host object does. Every other binary's ch_cfg has no such field, and
// TEST_CPU_CFG does nothing there.
#ifndef CH_TEST_CPU_H
#define CH_TEST_CPU_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "cfg.h"

#ifdef CH_CPU_RUNTIME
// The description each configuration a host test builds takes, unless one of its rows sets
// another. No path reads a bit past CH_CPU_PROBED yet, so the probe's bit alone.
#ifndef TEST_CPU
#define TEST_CPU CH_CPU_PROBED
#endif
#define TEST_CPU_CFG(cfg) ((cfg).cpu = TEST_CPU)

// Every bit a host object defines on the architecture this binary targets: the three of every
// host object, and on x86-64 CH_CPU_AVX2 and CH_CPU_VAES. It is written here apart from cpu_cfg.h's
// CH_CPU_DEFINED, so a wrong set there fails a row.
#define TEST_CPU_COMMON (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES | CH_CPU_CONSTANT_TIME_MULTIPLY)
#ifdef __x86_64__
#define TEST_CPU_ALL (TEST_CPU_COMMON | CH_CPU_AVX2 | CH_CPU_VAES)
#else
#define TEST_CPU_ALL TEST_CPU_COMMON
#endif

// The values every init call and ch_srv_check refuse: 0, which a caller that never set the field
// leaves; every defined bit but CH_CPU_PROBED; the first bit past CH_CPU_VAES, which no
// architecture defines; the top bit; and on arm64 each x86-64 bit, which an arm64 object refuses
// rather than ignores. Then the two they take at the edges: CH_CPU_PROBED alone, and every bit
// the architecture defines.
static const uint32_t test_cpu_values[] = {
    0,
    TEST_CPU_ALL & ~(uint32_t)CH_CPU_PROBED,
    CH_CPU_PROBED | (CH_CPU_VAES << 1),
    CH_CPU_PROBED | 0x80000000U,
#ifndef __x86_64__
    CH_CPU_PROBED | CH_CPU_AVX2,
    CH_CPU_PROBED | CH_CPU_VAES,
#endif
    CH_CPU_PROBED,
    TEST_CPU_ALL,
};
#define TEST_CPU_VALUES (sizeof test_cpu_values / sizeof test_cpu_values[0])

// Whether every init call and ch_srv_check take test_cpu_values[i]: the last two alone.
static inline int test_cpu_taken(size_t i) {
    return i + 2 >= TEST_CPU_VALUES;
}
#else
#define TEST_CPU_CFG(cfg) ((void)(cfg))
#endif

// Clears cfg, and in a host binary gives it TEST_CPU: where every configuration a loop test
// builds starts.
static inline void test_cfg_clear(ch_cfg *cfg) {
    memset(cfg, 0, sizeof *cfg);
    TEST_CPU_CFG(*cfg);
}

#endif
