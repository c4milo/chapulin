// chacha20_avx512.c as a host object compiles it, under CH_CPU_RUNTIME, for
// bin/chacha20_equiv_test, for the reason test/chacha20_equiv_vector.c
// gives chacha20_vector.c a translation unit of its own, and avx512_wipe.c,
// which the kernel calls before it returns, under the same define. On a
// target other than x86-64 both compile to nothing.
#define CH_CPU_RUNTIME
#include "chacha20_avx512.c"

#include "avx512_wipe.c"
