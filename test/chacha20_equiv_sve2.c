// chacha20_sve2.c as a host object compiles it, under CH_CPU_RUNTIME, for
// bin/chacha20_equiv_test, for the reason test/chacha20_equiv_vector.c
// gives chacha20_vector.c a translation unit of its own: the copy holds
// the 128-bit path's file-local names. On x86-64, and under a compiler
// without <arm_neon_sve_bridge.h>, it compiles to nothing.
#define CH_CPU_RUNTIME
#include "chacha20_sve2.c"
