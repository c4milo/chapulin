// poly1305_ifma.c as an x86-64 host object compiles it, its native copy
// under CH_CPU_RUNTIME, for bin/poly1305_equiv_test, for the reason
// test/poly1305_equiv_avx2.c gives the AVX2 kernel a unit of its own, and
// avx512_wipe.c, which the kernel calls before it returns, under the same
// define. On a target other than x86-64 both compile to nothing.
//
// ct_wipe.c compiles here too, ct_wipe renamed, for the reason
// test/poly1305_equiv_vector.c compiles it: the compiler sees ct_wipe's
// body where poly1305_ifma_blocks calls it and can inline it, and the
// residue check in test/poly1305_equiv_residue.h fails if the powers of r
// it was to write zero over are still on the stack.
#define CH_CPU_RUNTIME
#define ct_wipe ifma_ct_wipe

// Before ct_wipe.c, for the reason test/poly1305_equiv_vector.c gives.
#include "widemul_native.h"

#include "ct_wipe.c"
#include "poly1305_ifma_native.c"

#include "avx512_wipe.c"
