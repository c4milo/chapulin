// The ML-DSA-87 variant of the walker proof (docs/decisions.md 157),
// at the ECDSA variant's full two-entry bound of 256 bytes: the stubs
// may consume nothing, so every walker state is reachable. It proves the
// walker's TBS span, which ML-DSA-87 verifies whole, readable in the
// caller's buffer, and the 2592-byte key copy. The arm builds under
// PROFILE=cnsa2 alone, so the variant states the profile's defines.
#define CH_PROFILE_CNSA2 1
#define CH_MLKEM_1024 1
#define CH_SUITE_AES_GCM 1
#define CH_AES_EXTERN 1
#define CH_AES_EXTERN_CONSTANT_TIME 1
#define CH_PIN_MLDSA 1
#include "x509parse_harness.c"
