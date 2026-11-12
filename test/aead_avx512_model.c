// chacha20_avx512.c and aead_avx512.c compiled over the lane models,
// test/chacha20_avx512_model_lanes.h and test/poly1305_ifma_model_lanes.h,
// under second names, so that any host runs the AVX-512 one pass's own text
// and one binary can hold it beside the instructions.
// CH_AEAD_AVX512_MODEL and CH_CHACHA20_AVX512_MODEL make the two files
// include the models in place of the instructions and declare their entries
// on any architecture, and CH_POLY1305_IFMA_MODEL makes poly1305_ifma.h
// declare the group's constants. Only test units define them, and
// test/widemul-builds.sh refuses a library build that names them.
//
// The unit defines CH_CPU_RUNTIME, for ct.h's 64x64->128 multiply, which
// the IFMA model's two multiplications run on, and for aead_avx512.c's
// native copy, whose poly1305_update is the library's
// poly1305_update_native. bin/aead_avx512_equiv_test passes -DCH_CPU_RUNTIME
// for its other units, so the unit defines it only where the command line
// did not; it passes none of the model defines. The #defines rename every
// function the two files define outside the unit.
#ifndef CH_CPU_RUNTIME
#define CH_CPU_RUNTIME
#endif
#define CH_AEAD_AVX512_MODEL 1
#define CH_CHACHA20_AVX512_MODEL 1
#define CH_POLY1305_IFMA_MODEL 1

#define chacha20_avx512_xor aead_avx512_model_keystream
#define aead_avx512_seal aead_avx512_model_seal
#define aead_avx512_open aead_avx512_model_open

#include "chacha20_avx512.c"

#include "aead_avx512.c"
