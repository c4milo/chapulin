// chacha20_avx2.c under CH_CHACHA_VECTOR, for bin/chacha20_equiv_test,
// for the reason test/chacha20_equiv_vector.c gives chacha20_vector.c a
// translation unit of its own. The two vector sources share file-local
// names, so each takes a unit apart from the other. On a target other
// than x86-64 the kernel compiles to nothing.
#define CH_CHACHA_VECTOR
#include "chacha20_avx2.c"
