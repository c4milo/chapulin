// The arm of the aead_avx512 proof in clang's layout of a pass's groups
// (docs/decisions.md 238), for a message that ends in a row pass of 37
// bytes beside the last whole pass, so the layout's rounds run beside the
// rows. See aead_avx512_harness.c for what the harness proves.
#define AEAD_AVX512_CHUNKS_AFTER_HALF_ROUNDS 1
#define AEAD_AVX512_PROOF_REST 37

#include "aead_avx512_harness.c"
