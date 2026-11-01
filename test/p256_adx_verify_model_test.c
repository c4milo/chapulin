// test/p256_verify_equiv_test.c's cases with the host arm on the x86-64
// field's copy of the wide verifier (p256_adx.h), over the model of its two
// assembly routines (test/p256_adx_model.h), against the 32-bit verifier,
// on every host. The Makefile builds every unit under CH_P256_ADX_MODEL.
#define P256_VERIFY_EQUIV_ADX 1
#define P256_VERIFY_EQUIV_NAME "p256_adx_verify_model"
#include "p256_verify_equiv_test.c"
