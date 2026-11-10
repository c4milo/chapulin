// test/p256_equiv_test.c's cases on the arm64 field's copy of the wide files
// (p256_arm64.h) over the model of its two assembly routines
// (test/p256_arm64_model.h), against the files under their own names, on
// every host. The Makefile builds every unit under CH_P256_ARM64_MODEL, so
// widemul.h and p256.c dispatch to the copy on x86-64 too.
// bin/p256_arm64_equiv_test then holds the assembly to the model on arm64
// (docs/decisions.md 215).
#define P256_EQUIV_ARM64 1
#define P256_EQUIV_NAME "p256_arm64_model"
#include "p256_equiv_test.c"
