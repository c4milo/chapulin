// The ML-DSA-87 variant of the x509ca proof (docs/decisions.md 157):
// same harness, with the 2592-byte CH_X509_KEY_MAX the walk copies into
// and wipes. The build's CH_X509_MAX is 7808, and at that bound the
// formula passed 8 GB in 17 s. So the proof sets CH_X509_MAX to 2688,
// the override cfg.h admits. The stub's key length still runs past
// CH_X509_KEY_MAX, so the entry's length check meets both sides, and the
// walk reads CH_X509_MAX nowhere else. The arm builds under
// PROFILE=cnsa2 alone, so the variant states the profile's defines. A
// proof name is one launch line, so the variant gets its own file, the
// x509ca_ecdsa precedent.
#define CH_X509_MAX 2688
#define CH_PROFILE_CNSA2 1
#define CH_MLKEM_1024 1
#define CH_SUITE_AES_GCM 1
#define CH_AES_EXTERN 1
#define CH_AES_EXTERN_CONSTANT_TIME 1
#define CH_PIN_MLDSA 1
#include "x509ca_harness.c"
