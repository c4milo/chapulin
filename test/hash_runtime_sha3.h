// bin/hash_runtime_test's predicate and check for SHA-3 (docs/decisions.md 99 and 217).
// test/hash_runtime_test.c alone includes this file, after it defines calls_on.
//
// sha3.h's sha3_on_instructions picks sha3_hw.c's code where the value holds
// CH_CPU_CONSTANT_TIME_SHA3 in an arm64 object that clang compiled, and where it holds
// CH_CPU_BMI1 and CH_CPU_BMI2_ADX in an x86-64 one. test/hash_runtime_sha3_count.c counts the
// calls on each path and runs each on sha3.c. On x86-64 the binary runs the SHA-3 rows under each
// of its 256 values once more with each set of those two bits, sha3_copy_bits. The other rows do
// not take them: CH_CPU_BMI2_ADX beside the multiply bit runs P-256 on MULX and ADX, which a CPU
// that runs the binary may lack.
#ifndef CH_TEST_HASH_RUNTIME_SHA3_H
#define CH_TEST_HASH_RUNTIME_SHA3_H

#include <stdio.h>

#include "hash_runtime_count.h"
#include "sha3.h"

// sha3_hw.c's calls where clang compiled an arm64 object and the value holds the SHA-3 bit, and
// in an x86-64 object where it holds both CH_CPU_BMI1 and CH_CPU_BMI2_ADX.
static int names_sha3(uint32_t cpu) {
#ifdef CH_KECCAK_INSTRUCTIONS
    return (cpu & CH_CPU_CONSTANT_TIME_SHA3) != 0;
#elif defined(__x86_64__)
    return (cpu & CH_CPU_BMI1) != 0 && (cpu & CH_CPU_BMI2_ADX) != 0;
#else
    (void)cpu;
    return 0;
#endif
}

// Whether the SHA-3 calls since the last reset are counted, all on the path names_sha3 names,
// with a report of the calls where they are not.
static int sha3_calls_ok(const char *name, uint32_t cpu, const hash_calls *counted) {
    int ok = calls_on(names_sha3(cpu), counted, &sha3_portable_calls, &sha3_hw_calls);
    if (!ok) {
        (void)fprintf(stderr,
                      "hash runtime: %s under ch_cfg.cpu 0x%x: SHA-3 made %lu, %lu and %lu calls "
                      "on sha3.c and %lu, %lu and %lu on sha3_hw.c\n",
                      name, (unsigned)cpu, sha3_portable_calls.updates, sha3_portable_calls.finals,
                      sha3_portable_calls.whole_messages, sha3_hw_calls.updates,
                      sha3_hw_calls.finals, sha3_hw_calls.whole_messages);
    }
    return ok;
}

// The sets of the two bits that pick sha3_hw.c's copy on x86-64, which the binary adds to each of
// its 256 values. On arm64 the SHA-3 bit is among the eight bits of those values.
#ifdef __x86_64__
static const uint32_t sha3_copy_bits[] = {0, CH_CPU_BMI2_ADX, CH_CPU_BMI1,
                                          CH_CPU_BMI2_ADX | CH_CPU_BMI1};
#else
static const uint32_t sha3_copy_bits[] = {0};
#endif

#endif
