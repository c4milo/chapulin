// mlkem_poly.c, poly1305.c, rsa_sign.c and x25519.c under their own
// names, with the entries widemul.h dispatches to under
// test/widemul_count_names.h's second names (test/widemul_runtime_count.h).
// The four define no static name twice, so one unit holds them.
// p256_scalar.c takes a unit of its own, because it and rsa_sign.c both
// define mont_mul, and p256_point.c takes one beside it.
#include "widemul_count_names.h"

#include "mlkem_poly.c"
#include "poly1305.c"
#include "rsa_sign.c"
#include "x25519.c"
