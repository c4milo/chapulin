// X25519=wide under a second name. test/x25519_equiv_portable.c states why
// the renames are here and what they rewrite.
//
// CH_X25519_WIDE is defined here rather than on the compile line because
// the same line compiles test/x25519_equiv_portable.c, which must build the
// 16-limb field. x25519_wide.c is included here for the same reason: its
// body compiles only under that define. The compile line supplies
// CH_NATIVE_MUL128, the assertion ct.h asks of every X25519=wide build.
#define CH_X25519_WIDE 1
#define x25519 x25519_wide
#define x25519_base x25519_base_wide

#include "x25519.c"
#include "x25519_wide.c"
