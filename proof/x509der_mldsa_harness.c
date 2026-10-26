// The ML-DSA-87 variant of the x509der proof (docs/decisions.md 157):
// same harness, the third SPKI arm, which reads a 2592-byte key. The
// arm builds under PROFILE=cnsa2 alone, so the variant states the
// profile's defines. A proof name is one launch line, so the variant
// gets its own file, the x509der_ecdsa precedent.
#define CH_PROFILE_CNSA2 1
#define CH_MLKEM_1024 1
#define CH_SUITE_AES_GCM 1
#define CH_AES_EXTERN 1
#define CH_AES_EXTERN_CONSTANT_TIME 1
#define CH_PIN_MLDSA 1
#include "x509der_harness.c"
