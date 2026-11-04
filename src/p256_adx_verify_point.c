// p256_wide_verify_point.c compiled once more under p256_adx_names.h's
// names, on the x86-64 P-256 field (p256_adx.h): the verifier's Jacobian
// points and its sum u1 G + u2 Q.
#include "p256_adx.h"

#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_P256_ADX_MODEL))
// After the renames, so they apply to every declaration the source includes.
#include "p256_adx_names.h"
// The products and squares the renames name.
#include "p256_adx_field_inline.h"
#include "p256_wide_verify_point.c"
#endif
