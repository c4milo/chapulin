// test/aead_avx512_model.c's unit in clang's layout of a pass's groups:
// each of a group's four chunks after one half of a double round
// (docs/decisions.md 238). bin/aead_avx512_equiv_test holds it to the
// two-pass AEAD beside the unit in gcc's layout, under every compiler.
#define AEAD_AVX512_MODEL_HALVES 1

#include "aead_avx512_model.c"
