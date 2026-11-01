// test/p256_equiv_test.c's cases on the x86-64 field's copy of the wide
// files (p256_adx.h) over the model of its two assembly routines
// (test/p256_adx_model.h), against the files under their own names, on
// every host. The Makefile builds every unit under CH_P256_ADX_MODEL, so
// widemul.h and p256.c dispatch to the copy on arm64 too.
// bin/p256_adx_equiv_test then holds the assembly to the model on a CPU
// with BMI2 and ADX (docs/decisions.md 171).
#define P256_EQUIV_ADX 1
#define P256_EQUIV_NAME "p256_adx_model"
#include "p256_equiv_test.c"
