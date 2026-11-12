// The arm of the aead_avx512 proof whose message ends in a last pass of
// sixteen blocks over 300 bytes. See aead_avx512_harness.c for what the
// harness proves.
#define AEAD_AVX512_PROOF_REST 300

#include "aead_avx512_harness.c"
