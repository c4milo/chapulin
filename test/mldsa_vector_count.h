// The calls bin/mldsa_runtime_test counts into mldsa_vector.c, the lanes
// of an arm64 host object's ML-DSA-87 NTT (docs/decisions.md 172).
// test/mldsa_vector_count.c defines the four entries of mldsa_vector.h,
// each as a count and a call to mldsa_poly.c's loop that computes the same
// value, and the binary links that file in place of mldsa_vector.c. So the
// library's other sources run unchanged, no lane instruction runs, and the
// test reads which calls of the signer and the verifier took the lanes.
//
// The names are this test's alone, as test/hash_runtime_count.h's are.
#ifndef CH_TEST_MLDSA_VECTOR_COUNT_H
#define CH_TEST_MLDSA_VECTOR_COUNT_H

// How many times the library called each entry of mldsa_vector.h.
typedef struct {
    unsigned long ntt;
    unsigned long invntt;
    unsigned long pointwise;
    unsigned long pointwise_acc;
} mldsa_vector_calls;

extern mldsa_vector_calls mldsa_vector_counted;

#endif
