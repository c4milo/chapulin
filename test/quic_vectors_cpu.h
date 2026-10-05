// The passes bin/quic_test_hw runs its vectors under beside the two
// test/quic_vectors.c's main names: on the x86-64 kernels, and with every
// key derived on the CPU's SHA-256 instructions. Each sets
// test_initial_cpu, the value the Initial calls take (test/initial_cpu.h),
// and test_cpu, the value the level keys' calls take, and runs
// run_vectors again. A CPU without a pass's instructions skips it, and
// fails it where the environment requires them.
//
// Included by test/quic_vectors.c only, in a QUIC host object.
#ifndef CH_TEST_QUIC_VECTORS_CPU_H
#define CH_TEST_QUIC_VECTORS_CPU_H
#ifdef CH_AES_TWO_CIPHERS

#include "hash_instructions_cpu.h"
#include "x86_kernels_cpu.h"

#ifdef __x86_64__
// Every vector once more with every bit an x86-64 host object defines, on
// a CPU that has VAES and VPCLMULQDQ, and so AVX2: gcm.c then runs the
// whole blocks of the Initial keys and of SP 800-38D's keys on
// gcm_vaes.c's kernels, and Appendix A.5's packet its ChaCha20 keystream
// on chacha20_avx2.c's. A CPU without the instructions skips the pass, and
// under CH_REQUIRE_X86_KERNELS=1 fails it (test/x86_kernels_cpu.h). The
// value leaves out a hash bit whose instructions the CPU lacks.
static void run_vectors_on_kernels(void) {
    if (!x86_cpu_has_vaes()) {
        if (x86_kernels_required()) {
            (void)fprintf(stderr, "quic vectors: this CPU lacks VAES or VPCLMULQDQ, and "
                                  "CH_REQUIRE_X86_KERNELS is 1\n");
            failures++;
            return;
        }
        (void)printf("quic vectors: SKIP the pass on the x86-64 kernels: this CPU lacks VAES or "
                     "VPCLMULQDQ\n");
        return;
    }
    test_initial_cpu = TEST_CPU_ALL & ~test_cpu_absent_hash_bits(TEST_CPU_ALL);
    test_cpu = test_initial_cpu;
    run_vectors();
}
#endif

// Every vector once more with the SHA-256 bit beside the AES bit
// (docs/decisions.md 93). RFC 9001 Appendix A and RFC 9369 Appendix A fix
// the keys HKDF derives from each salt, connection ID and traffic secret,
// so on this pass they answer for sha256_hw.c and for the copies of HKDF
// over it. A CPU without the instructions skips the pass, and under
// CH_REQUIRE_HASH_INSTRUCTIONS=1 fails it (test/hash_instructions_cpu.h).
static void run_vectors_on_hash_instructions(void) {
    if (!cpu_has_sha256_instructions()) {
        if (hash_instructions_required()) {
            (void)fprintf(stderr, "quic vectors: this CPU lacks the SHA-256 instructions, and "
                                  "CH_REQUIRE_HASH_INSTRUCTIONS is 1\n");
            failures++;
            return;
        }
        (void)printf("quic vectors: SKIP the pass on the SHA-256 instructions: this CPU lacks "
                     "them\n");
        return;
    }
    test_initial_cpu = CH_CPU_PROBED | CH_CPU_CONSTANT_TIME_AES | CH_CPU_CONSTANT_TIME_SHA256;
    test_cpu = test_initial_cpu;
    run_vectors();
}

#endif // CH_AES_TWO_CIPHERS
#endif
