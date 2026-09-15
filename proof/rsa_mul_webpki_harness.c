// The TRUST=webpki variant of the rsa_mul proof: the same harness at the
// 128 limbs LIMBS_MAX resolves to under CH_TRUST_WEBPKI (RSA-4096,
// rsa.h). A proof name is one launch line, so the variant gets its own
// file, the pem_ecdsa precedent.
#define CH_TRUST_WEBPKI 1
#include "rsa_mul_harness.c"
