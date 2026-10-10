// rsa_avx2.c on the AVX2 instructions, as a host object compiles it, with
// test/rsa_avx2_entries.h after it, which gives the static functions
// bin/rsa_avx2_equiv_test calls the prefix rsa_avx2_instructions_.
// rsa_avx2_public keeps its own name, which rsa_mont.c's rsa_vp1_cpu
// calls, so the binary links this unit in place of rsa_avx2.c. The whole
// unit compiles on x86-64 alone, as rsa_avx2.c does.
#include "rsa_avx2_test.h"

#include "rsa_avx2.c"

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)
#define RSA_AVX2_ENTRY(name) rsa_avx2_instructions_##name
#include "rsa_avx2_entries.h"
#endif
