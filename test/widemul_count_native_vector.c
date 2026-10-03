// poly1305_vector.c as its native copy, the one a CHACHA=vector host
// object holds. Its entry takes a second name here, and
// test/widemul_runtime_count.c defines poly1305_vector_blocks_native, the
// name poly1305_native.c's block loop calls, as a count and a call to it
// (test/widemul_runtime_count.h).
#include "widemul_native.h"

#undef poly1305_vector_blocks
#define poly1305_vector_blocks poly1305_vector_blocks_native_counted

#include "poly1305_vector.c"
