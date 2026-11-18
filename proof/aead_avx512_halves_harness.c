// The arm of the aead_avx512 proof in clang's layout of a pass's groups,
// each chunk of a group after one half of a double round
// (docs/decisions.md 238), for a message that ends on a whole pass. goto-cc
// takes gcc's layout, which aead_avx512_harness.c proves. See that file
// for what the harness proves.
#define AEAD_AVX512_CHUNKS_AFTER_HALF_ROUNDS 1

#include "aead_avx512_harness.c"
