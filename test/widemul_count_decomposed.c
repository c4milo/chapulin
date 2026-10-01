// mlkem_poly.c, poly1305.c, rsa_sign.c and x25519.c under their own
// names, with the entries widemul.h dispatches to under
// test/widemul_count_names.h's second names (test/widemul_runtime_count.h).
// test/widemul_count_native.c says why the four share one unit.
#include "widemul_count_names.h"

#include "mlkem_poly.c"
#include "poly1305.c"
#include "rsa_sign.c"
#include "x25519.c"
