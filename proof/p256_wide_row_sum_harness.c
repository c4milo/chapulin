// p256_wide_row's proof once more, on the 128-bit sums: the form of
// p256_wide_limb.h's two carry steps that gcc compiles for a machine other
// than x86-64. See p256_wide_row_harness.c for what it proves and for why
// one reference holds both forms.
#define P256_WIDE_CARRY P256_WIDE_CARRY_SUM
#include "p256_wide_row_harness.c"
