// x25519_adx.c, X25519's third copy in an x86-64 host object, with the one
// entry widemul.h dispatches to under a second name
// (test/widemul_runtime_count.h). The rename is here and not in
// test/widemul_count_names.h for test/widemul_count_wide.c's reason:
// x25519_adx.c renames x25519 itself to compile x25519.c's clamp and
// all-zero check inside it. On another architecture it compiles to
// nothing.
#define x25519_adx x25519_adx_counted

#include "x25519_adx.c"
