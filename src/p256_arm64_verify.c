// p256_wide_verify.c compiled once more under p256_arm64_names.h's names, on
// the arm64 P-256 field (p256_arm64.h): the check of an ECDSA signature's r
// and s.
#include "p256_arm64.h"

#if defined(CH_CPU_RUNTIME) && (defined(__aarch64__) || defined(CH_P256_ARM64_MODEL))
// After the renames, so they apply to every declaration the source includes.
#include "p256_arm64_names.h"
#include "p256_wide_verify.c"
#endif
