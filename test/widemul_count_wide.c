// x25519_wide.c, X25519's second copy in a host object, with the two
// entries widemul.h dispatches to under second names
// (test/widemul_runtime_count.h). The renames are here and not in
// test/widemul_count_names.h, because x25519_wide.c renames x25519 and
// x25519_base itself to compile x25519.c's clamp and all-zero check
// inside it, and that header renames the same two for the other units.
#define x25519_wide x25519_wide_counted
#define x25519_wide_base x25519_wide_base_counted

#include "x25519_wide.c"
