// The calls bin/hash_runtime_test counts into a host object's SHA-256, on
// each of its two paths (docs/decisions.md 93): sha256.c's three calls
// that hash, and the three of sha256_hw.c, which run on the CPU's SHA-256
// instructions. test/hash_runtime_count.c defines all six, each as a count
// and a call to sha256.c's code, and the binary links that file in place of
// sha256.c and sha256_hw.c. So the library's other sources run unchanged,
// no hash instruction runs, and the test reads which path each call of the
// library took, on any CPU.
//
// The names are this test's alone, as test/x86_kernels_count.h's are.
#ifndef CH_TEST_HASH_RUNTIME_COUNT_H
#define CH_TEST_HASH_RUNTIME_COUNT_H

// How many times the library called each of a path's three entries: the
// update, the final and the hash of one whole message.
typedef struct {
    unsigned long updates;
    unsigned long finals;
    unsigned long whole_messages;
} hash_calls;

// Calls to sha256_update, sha256_final and sha256_of.
extern hash_calls sha256_portable_calls;
// Calls to sha256_update_hw, sha256_final_hw and sha256_of_hw.
extern hash_calls sha256_hw_calls;

#endif
