// The calls bin/hash_runtime_test counts into a host object's SHA-256 and
// SHA-512, on each hash's two paths (docs/decisions.md 93): sha256.c's
// three calls that hash and sha512.c's five, and the same calls of
// sha256_hw.c and sha512_hw.c, which run on the CPU's hash instructions.
// test/hash_runtime_count.c defines them all, each as a count and a call
// to the portable code, and the binary links that file in place of
// sha256.c, sha256_hw.c, sha512.c and sha512_hw.c. So the library's other
// sources run unchanged, no hash instruction runs, and the test reads which
// path each call of the library took, on any CPU.
//
// The names are this test's alone, as test/x86_kernels_count.h's are.
#ifndef CH_TEST_HASH_RUNTIME_COUNT_H
#define CH_TEST_HASH_RUNTIME_COUNT_H

// How many times the library called a path's entries: the update, the
// finals and the hashes of one whole message. SHA-512's two finals count
// together, and so do its two whole-message calls, SHA-384's and
// SHA-512's.
typedef struct {
    unsigned long updates;
    unsigned long finals;
    unsigned long whole_messages;
} hash_calls;

// Calls to sha256_update, sha256_final and sha256_of.
extern hash_calls sha256_portable_calls;
// Calls to sha256_update_hw, sha256_final_hw and sha256_of_hw.
extern hash_calls sha256_hw_calls;
// Calls to sha512_update, sha512_final, sha384_final, sha512_of and
// sha384_of.
extern hash_calls sha512_portable_calls;
// Calls to the same five with _hw after their names, which an arm64 host
// object alone holds. On x86-64 nothing counts here.
extern hash_calls sha512_hw_calls;

#endif
