// p256_wide_inverse_steps's proof once more, on the 128-bit difference: the
// form of the step's subtraction that gcc compiles for a machine other than
// x86-64, whose top word is the swap mask (p256_wide_sub_mask in
// p256_wide_word.h, docs/decisions.md 243). See
// p256_wide_inverse_steps_harness.c for what it proves.
#define P256_WIDE_CARRY P256_WIDE_CARRY_SUM
#include "p256_wide_inverse_steps_harness.c"
