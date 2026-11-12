// The arm of the aead_avx512 proof whose message ends in a row pass of 37
// bytes beside the last whole pass. See aead_avx512_harness.c for what the
// harness proves.
#define AEAD_AVX512_PROOF_REST 37

#include "aead_avx512_harness.c"
