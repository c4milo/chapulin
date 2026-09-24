// X25519=portable, the 16-limb field, under a second name, so one binary can
// hold both fields: x25519.c defines x25519 and x25519_base whichever field
// it compiles, and a library object holds one field only.
//
// The two #defines rewrite both the definitions in x25519.c and the
// declarations it reads from x25519.h, because they are in effect before
// that header is read. test/x25519_equiv_wide.c is the same file for
// X25519=wide, and test/x25519_equiv_test.c calls both.
#define x25519 x25519_portable
#define x25519_base x25519_base_portable

#include "x25519.c"
