// A host object's native copy of Poly1305, poly1305_native.c with
// poly1305_vector_native.c, under CH_CPU_RUNTIME, for
// bin/poly1305_equiv_test. That binary also links poly1305.c compiled
// without the define, the loop alone on the 16x16 decomposition, as a
// device object runs it, and one compile line cannot give one source two
// sets of defines, so this translation unit compiles the copy that holds
// the vector path. The copy takes the names widemul_native.h gives it,
// poly1305_init_native, poly1305_update_native, poly1305_final_native and
// poly1305_vector_blocks_native, so nothing here renames it.
//
// ct_wipe.c compiles here too, ct_wipe renamed, so the compiler sees
// ct_wipe's body where poly1305_vector_blocks calls it
// and can inline it, as link-time optimization or a build that compiles
// every source as one unit would. The wipe then ends a frame that nothing
// reads again, which is where a compiler deletes a plain memset, and the
// residue check in test/poly1305_equiv_residue.h fails if the powers of r
// it was to write zero over are still on the stack.
#define CH_CPU_RUNTIME
#define ct_wipe vector_ct_wipe

// Before ct_wipe.c, whose first line reads ct.h: ct.h takes the native
// multiply only where it has seen widemul_native.h's CH_WIDEMUL_NATIVE_COPY
// by then, and reads nothing the second time a file includes it.
#include "widemul_native.h"

#include "ct_wipe.c"
#include "poly1305_native.c"
#include "poly1305_vector_native.c"

#ifndef CH_POLY1305_VECTOR
#error "bin/poly1305_equiv_test needs the vector Poly1305 in a host object's native copy"
#endif
