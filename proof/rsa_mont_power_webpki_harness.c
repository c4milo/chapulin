// The TRUST=webpki variant of the rsa_mont_power proof: the same harness at
// 32 words and at the 64 words the bound resolves to under CH_TRUST_WEBPKI
// (RSA-4096, rsa.h). A proof name is one launch line, so the variant gets
// its own file, the rsa_mul_webpki precedent.
#define CH_TRUST_WEBPKI 1
#include "rsa_mont_power_harness.c"
