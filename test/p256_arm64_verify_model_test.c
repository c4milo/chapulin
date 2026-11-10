// test/p256_verify_equiv_test.c's cases with the host arm on the arm64
// field's copy of the wide verifier (p256_arm64.h), over the model of its two
// assembly routines (test/p256_arm64_model.h), against the 32-bit verifier,
// on every host. The Makefile builds every unit under CH_P256_ARM64_MODEL.
#define P256_VERIFY_EQUIV_ARM64 1
#define P256_VERIFY_EQUIV_NAME "p256_arm64_verify_model"
#include "p256_verify_equiv_test.c"
