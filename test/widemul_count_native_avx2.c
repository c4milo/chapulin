// poly1305_avx2.c as its native copy, the one an x86-64 host object
// holds, in a unit apart from test/widemul_count_native_vector.c's
// because the two vector sources share file-local names. Its entry takes
// a second name here, and test/widemul_runtime_count.c defines
// poly1305_avx2_blocks_native, the name poly1305_native.c's block loop
// calls, as a count and a call to it (test/widemul_runtime_count.h). On a
// target other than x86-64 the kernel compiles to nothing.
#include "widemul_native.h"

#undef poly1305_avx2_blocks
#define poly1305_avx2_blocks poly1305_avx2_blocks_native_counted

#include "poly1305_avx2.c"
