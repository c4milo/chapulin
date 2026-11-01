// The SHAKE calls bin/mldsa_runtime_test counts: which of ML-DSA-87's
// hashes ran on sha3.c and which took the path of sha3_hw.c under each
// ch_cfg.cpu value. test/mldsa_sha3_count.c compiles sha3.c with its two
// SHAKE entries renamed, and defines shake_absorb and shake_squeeze as a
// count and a call to them. In an arm64 host object that clang compiled
// it also defines shake_absorb_hw and shake_squeeze_hw as a count and the
// same portable call, so no SHA-3 instruction runs and the binary gives
// the same verdict on every CPU of its architecture.
//
// The names are this test's alone, as test/hash_runtime_count.h's are.
#ifndef CH_TEST_MLDSA_SHA3_COUNT_H
#define CH_TEST_MLDSA_SHA3_COUNT_H

// How many SHAKE absorb and squeeze calls ran on each path.
typedef struct {
    unsigned long absorb;
    unsigned long squeeze;
    unsigned long absorb_hw;
    unsigned long squeeze_hw;
} mldsa_sha3_calls;

extern mldsa_sha3_calls mldsa_sha3_counted;

#endif
