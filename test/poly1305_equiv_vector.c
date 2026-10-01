// poly1305.c and poly1305_vector.c under CH_CHACHA_VECTOR, for
// bin/poly1305_equiv_test. That binary also links poly1305.c compiled
// without the define, the portable loop alone, and one compile line
// cannot give one source two sets of defines, so this translation unit
// compiles the vector build of poly1305.c a second time, its three
// external names renamed with a vector_ prefix. The host CFLAGS assert
// CH_NATIVE_WIDEMUL, so poly1305_vector.h turns the path on here.
//
// ct_wipe.c compiles here too, ct_wipe renamed with the same prefix, so
// the compiler sees ct_wipe's body where poly1305_vector_blocks calls it
// and can inline it, as link-time optimization or a build that compiles
// every source as one unit would. The wipe then ends a frame that nothing
// reads again, which is where a compiler deletes a plain memset, and the
// residue check in test/poly1305_equiv_residue.h fails if the powers of r
// it was to write zero over are still on the stack.
#define CH_CHACHA_VECTOR
#define poly1305_init vector_poly1305_init
#define poly1305_update vector_poly1305_update
#define poly1305_final vector_poly1305_final
#define ct_wipe vector_ct_wipe

#include "ct_wipe.c"
#include "poly1305.c"
#include "poly1305_vector.c"

#ifndef CH_POLY1305_VECTOR
#error                                                                                             \
    "bin/poly1305_equiv_test needs CH_NATIVE_WIDEMUL without CH_CT_WIDEMUL, as the host CFLAGS set"
#endif
