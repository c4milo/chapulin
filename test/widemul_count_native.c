// mlkem_poly.c, poly1305.c, rsa_sign.c and x25519.c as their native
// copies, with the entries widemul.h dispatches to under
// test/widemul_count_names.h's second names (test/widemul_runtime_count.h).
// The four define no static name twice, so one unit holds them;
// p256_field.c and p256_scalar.c each take a unit of their own, because
// both define mont_mul, RR and ONE.
#include "widemul_native.h"

#include "widemul_count_names.h"

#include "mlkem_poly.c"
#include "poly1305.c"
#include "rsa_sign.c"
#include "x25519.c"
