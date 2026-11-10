// p256_wide_verify_point.c compiled once more under p256_arm64_names.h's
// names, on the arm64 P-256 field (p256_arm64.h): the verifier's Jacobian
// points and its sum u1 G + u2 Q.
#include "p256_arm64.h"

#if defined(CH_CPU_RUNTIME) && (defined(__aarch64__) || defined(CH_P256_ARM64_MODEL))
// After the renames, so they apply to every declaration the source includes.
#include "p256_arm64_names.h"
// The products and squares the renames name.
#include "p256_arm64_field_inline.h"
#include "p256_wide_verify_point.c"
#endif
