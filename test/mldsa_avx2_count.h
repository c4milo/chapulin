// The calls bin/mldsa_runtime_test counts into mldsa_avx2.c, the
// four-way sampler of an x86-64 host object's ML-DSA-87 matrix
// (docs/decisions.md 178). test/mldsa_avx2_count.c defines
// mld_sample_ntt_avx2 as a count and a call to mld_sample_ntt for each
// entry, and the binary links that file in place of mldsa_avx2.c and
// keccak_avx2.c. So no AVX2 instruction runs, and the test reads which
// rows of the signer and the verifier took the four-way sampler.
//
// The names are this test's alone, as test/mldsa_vector_count.h's are.
#ifndef CH_TEST_MLDSA_AVX2_COUNT_H
#define CH_TEST_MLDSA_AVX2_COUNT_H

// How many times the library called mld_sample_ntt_avx2, and the entries
// those calls sampled.
typedef struct {
    unsigned long calls;
    unsigned long entries;
} mldsa_avx2_calls;

extern mldsa_avx2_calls mldsa_avx2_counted;

#endif
