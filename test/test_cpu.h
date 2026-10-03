// What a host test binary states about the CPU in ch_cfg.cpu (cpu_cfg.h, docs/decisions.md 89),
// and the values its rows try at every init call and ch_srv_check. A host binary compiles with
// -DCH_CPU_RUNTIME, as a host object does. Every other binary's ch_cfg has no such field, and
// TEST_CPU_CFG does nothing there.
#ifndef CH_TEST_CPU_H
#define CH_TEST_CPU_H

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cfg.h"

#ifdef CH_CPU_RUNTIME
// The description each configuration a host test builds takes, unless one of its rows sets
// another. Every host binary states CH_CPU_CONSTANT_TIME_MULTIPLY, so its operations built on the
// widening multiply run the native copies, as the host test flags' CH_NATIVE_WIDEMUL runs every
// other binary's, and its rows that count each copy's calls clear the bit for one end or both. A
// suite binary's rows run the AES-GCM suites, which a session runs only when its caller sets
// CH_CPU_CONSTANT_TIME_AES (suite.h), so it states that bit too. Every other host binary leaves
// it clear, so its QUIC Initial packets run on the table, and the suite binaries' rows run them on
// the instructions.
#ifndef TEST_CPU
#ifdef CH_SUITE_AES_GCM
#define TEST_CPU (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES | CH_CPU_CONSTANT_TIME_MULTIPLY)
#else
#define TEST_CPU (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_MULTIPLY)
#endif
#endif

// The value this binary runs under: TEST_CPU, unless its one argument names another
// (test_take_cpu). The Makefile runs each vector binary once for each set of bits that changes a
// path, and the binary hands its answers on from this value (test/test_widemul.h).
static uint32_t test_cpu = TEST_CPU;
#define TEST_CPU_CFG(cfg) ((cfg).cpu = test_cpu)

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

// Takes a host binary's one argument, a number such as 0x5, into test_cpu and prints it, and
// exits with status 2 for an argument that is not a 32-bit number. With no argument test_cpu
// keeps TEST_CPU. Every other binary takes no argument and prints nothing.
static inline void test_take_cpu(int argc, char **argv) {
#ifdef CH_CPU_RUNTIME
    if (argc > 1) {
        char *end = NULL;
        unsigned long bits = strtoul(argv[1], &end, 0);
        if (*argv[1] == 0 || *end != 0 || bits > UINT32_MAX) {
            (void)printf("%s: %s is not a ch_cfg.cpu value\n", argv[0], argv[1]);
            exit(2);
        }
        test_cpu = (uint32_t)bits;
    }
    (void)printf("%s under ch_cfg.cpu 0x%" PRIx32 "\n", argv[0], test_cpu);
#else
    (void)argc;
    (void)argv;
#endif
}

// Clears cfg, and in a host binary gives it test_cpu: where every configuration a loop test
// builds starts.
static inline void test_cfg_clear(ch_cfg *cfg) {
    memset(cfg, 0, sizeof *cfg);
    TEST_CPU_CFG(*cfg);
}

#endif
