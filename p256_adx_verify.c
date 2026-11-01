// p256_wide_verify.c compiled once more under p256_adx_names.h's names, on
// the x86-64 P-256 field (p256_adx.h): the check of an ECDSA signature's r
// and s.
#include "p256_adx.h"

#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_P256_ADX_MODEL))
// After the renames, so they apply to every declaration the source includes.
#include "p256_adx_names.h"
#include "p256_wide_verify.c"
#endif
