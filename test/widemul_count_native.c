// mlkem_poly.c, poly1305.c and rsa_sign.c as their native
// copies, with the entries widemul.h dispatches to under
// test/widemul_count_names.h's second names (test/widemul_runtime_count.h).
// The three define no static name twice, so one unit holds them.
#include "widemul_native.h"

#include "widemul_count_names.h"

#include "mlkem_poly.c"
#include "poly1305.c"
#include "rsa_sign.c"
