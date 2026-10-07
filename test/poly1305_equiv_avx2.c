// poly1305_avx2.c as an x86-64 host object compiles it, its native copy
// under CH_CPU_RUNTIME, for bin/poly1305_equiv_test, for the reason
// test/poly1305_equiv_vector.c gives the vector path a translation unit of
// its own: the two vector sources share file-local names, so each takes a
// unit apart from the other. On a target other than x86-64 the kernel
// compiles to nothing.
//
// ct_wipe.c compiles here too, ct_wipe renamed, for the reason
// test/poly1305_equiv_vector.c compiles it: the compiler sees ct_wipe's
// body where poly1305_avx2_blocks calls it and can inline it, and the
// residue check in test/poly1305_equiv_residue.h fails if the powers of r
// it was to write zero over are still on the stack.
#define CH_CPU_RUNTIME
#define ct_wipe avx2_ct_wipe

// Before ct_wipe.c, for the reason test/poly1305_equiv_vector.c gives.
#include "widemul_native.h"

#include "ct_wipe.c"
#include "poly1305_avx2_native.c"
