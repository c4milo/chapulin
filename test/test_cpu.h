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
#include "hash_instructions_cpu.h"
#include "x86_kernels_cpu.h"

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
// path, and the binary hands its answers on from this value (test/test_widemul.h,
// test/test_aead.h).
static uint32_t test_cpu = TEST_CPU;
#define TEST_CPU_CFG(cfg) ((cfg).cpu = test_cpu)
// What a test hands a call that takes a session's ch_cfg.cpu first, as quic_packet.h's do: the
// value this binary runs under.
#define TEST_SESSION_CPU test_cpu
// Gives d, a record direction a test keys itself, the value an init call writes into a session's
// directions (record.h), before the test keys it: rec_dir_init reads the field for the hash that
// derives the key and leaves it as it found it, so a direction a test declares and keys without
// this line first would read whatever its storage held. The write goes through the direction's
// address, because cppcheck 2.22 reads `(d).cpu = ...` on a direction no call has written yet as
// a read of the whole direction.
#define TEST_CPU_DIR(d) ((&(d))->cpu = test_cpu)

// Every bit a host object defines on the architecture this binary targets: the four of every
// host object, on x86-64 CH_CPU_AVX2 and CH_CPU_VAES, and on arm64 CH_CPU_CONSTANT_TIME_SHA512
// and CH_CPU_CONSTANT_TIME_SHA3. It is written here apart from cpu_cfg.h's CH_CPU_DEFINED, so a
// wrong set there fails a row.
#define TEST_CPU_COMMON                                                                            \
    (CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES | CH_CPU_CONSTANT_TIME_MULTIPLY |                    \
     CH_CPU_CONSTANT_TIME_SHA256)
#ifdef __x86_64__
#define TEST_CPU_ALL (TEST_CPU_COMMON | CH_CPU_AVX2 | CH_CPU_VAES)
#else
#define TEST_CPU_ALL (TEST_CPU_COMMON | CH_CPU_CONSTANT_TIME_SHA512 | CH_CPU_CONSTANT_TIME_SHA3)
#endif

// The values every init call and ch_srv_check refuse: 0, which a caller that never set the field
// leaves; every defined bit but CH_CPU_PROBED; the first bit past CH_CPU_CONSTANT_TIME_SHA3,
// which no architecture defines; the top bit; and each bit of the other architecture, which an
// object refuses rather than ignores: the two x86-64 bits on arm64, and the SHA-512 and SHA-3
// bits on x86-64. Then the two they take at the edges: CH_CPU_PROBED alone, and every bit the
// architecture defines.
static const uint32_t test_cpu_values[] = {
    0,
    TEST_CPU_ALL & ~(uint32_t)CH_CPU_PROBED,
    CH_CPU_PROBED | (CH_CPU_CONSTANT_TIME_SHA3 << 1),
    CH_CPU_PROBED | 0x80000000U,
#ifdef __x86_64__
    CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_SHA512,
    CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_SHA3,
#else
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

// The hash bits of value whose instructions this CPU lacks (test/hash_instructions_cpu.h). A
// session under such a bit dies of SIGILL at its first hash, as one whose caller described the
// CPU wrongly does.
static inline uint32_t test_cpu_absent_hash_bits(uint32_t value) {
    uint32_t absent = 0;
    if ((value & CH_CPU_CONSTANT_TIME_SHA256) != 0 && !cpu_has_sha256_instructions()) {
        absent |= CH_CPU_CONSTANT_TIME_SHA256;
    }
#ifdef __aarch64__
    if ((value & CH_CPU_CONSTANT_TIME_SHA512) != 0 && !cpu_has_sha512_instructions()) {
        absent |= CH_CPU_CONSTANT_TIME_SHA512;
    }
#endif
    return absent;
}

// test_cpu_values[i] as a row hands it to an init call. A value the call takes starts a session,
// which hashes its first message, so the row leaves out a hash bit whose instructions this CPU
// lacks: there the row holds that the call takes the other bits. A value the call refuses runs
// nothing and stays whole.
static inline uint32_t test_cpu_value(size_t i) {
    uint32_t value = test_cpu_values[i];
    if (!test_cpu_taken(i)) {
        return value;
    }
    return value & ~test_cpu_absent_hash_bits(value);
}

// The hash bits a row gives an end that states its hash instructions: each one an object runs
// a hash on, the SHA-256 bit and on arm64 the SHA-512 bit, where this CPU has the
// instructions, so 0 on a CPU with none of them. Where the environment requires the
// instructions (test/hash_instructions_cpu.h), a CPU that lacks any ends the binary with
// status 1.
#ifdef __aarch64__
#define TEST_CPU_HASH_BITS (CH_CPU_CONSTANT_TIME_SHA256 | CH_CPU_CONSTANT_TIME_SHA512)
#else
#define TEST_CPU_HASH_BITS CH_CPU_CONSTANT_TIME_SHA256
#endif
static inline uint32_t test_cpu_hash_bits(void) {
    uint32_t absent = test_cpu_absent_hash_bits(TEST_CPU_HASH_BITS);
    if (absent != 0 && hash_instructions_required()) {
        (void)fprintf(stderr,
                      "this CPU lacks the instructions of hash bits 0x%" PRIx32 ", and "
                      "CH_REQUIRE_HASH_INSTRUCTIONS is 1\n",
                      absent);
        exit(1);
    }
    return TEST_CPU_HASH_BITS & ~absent;
}
#else
#define TEST_CPU_CFG(cfg) ((void)(cfg))
#define TEST_SESSION_CPU 0U
#define TEST_CPU_DIR(d) ((void)sizeof(d))
#endif

#ifdef CH_CPU_RUNTIME
// The instructions test_cpu names and this CPU lacks, or NULL where it has them all: an x86-64
// kernel's, or a hash's. *required is whether the environment makes their absence a failure:
// CH_REQUIRE_X86_KERNELS for a kernel, which CI's x86-64 kernels job sets
// (test/x86_kernels_cpu.h), and CH_REQUIRE_HASH_INSTRUCTIONS for a hash
// (test/hash_instructions_cpu.h).
static inline const char *test_cpu_lacks(int *required) {
#ifdef __x86_64__
    *required = x86_kernels_required();
    if ((test_cpu & CH_CPU_AVX2) != 0 && !x86_cpu_has_avx2()) {
        return "AVX2";
    }
    if ((test_cpu & CH_CPU_VAES) != 0 && !x86_cpu_has_vaes()) {
        return "VAES or VPCLMULQDQ";
    }
#endif
    *required = hash_instructions_required();
    uint32_t absent = test_cpu_absent_hash_bits(test_cpu);
    if ((absent & CH_CPU_CONSTANT_TIME_SHA256) != 0) {
        return "the SHA-256 instructions";
    }
#ifdef __aarch64__
    if ((absent & CH_CPU_CONSTANT_TIME_SHA512) != 0) {
        return "the SHA-512 instructions";
    }
#endif
    return NULL;
}
#endif

// Ends a host binary whose test_cpu names instructions this CPU cannot run. A session whose
// caller described the CPU wrongly dies of SIGILL at the first such instruction, and so would
// this binary, so it prints SKIP and exits with status 0, or fails with status 1 where the
// environment requires the instructions (test_cpu_lacks). The library asks no CPU anything; a
// test may.
static inline void test_skip_absent_instructions(const char *binary) {
#ifdef CH_CPU_RUNTIME
    int required = 0;
    const char *lacks = test_cpu_lacks(&required);
    if (lacks == NULL) {
        return;
    }
    if (required) {
        (void)fprintf(stderr,
                      "%s: ch_cfg.cpu 0x%" PRIx32 " names %s, which this CPU lacks, and the "
                      "environment requires them\n",
                      binary, test_cpu, lacks);
        exit(1);
    }
    (void)printf("SKIP %s under ch_cfg.cpu 0x%" PRIx32 ": this CPU lacks %s\n", binary, test_cpu,
                 lacks);
    exit(0);
#else
    (void)binary;
#endif
}

// Takes a host binary's one argument, a number such as 0x5, into test_cpu and prints it, and
// exits with status 2 for an argument that is not a 32-bit number. With no argument test_cpu
// keeps TEST_CPU. A value that names instructions the CPU cannot run ends the binary there
// (test_skip_absent_instructions). Every other binary takes no argument and prints nothing.
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
    test_skip_absent_instructions(argv[0]);
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
