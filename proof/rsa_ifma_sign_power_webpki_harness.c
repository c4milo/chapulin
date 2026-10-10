// The TRUST=webpki variant of the rsa_ifma_sign_power proof: the same harness under
// CH_TRUST_WEBPKI (RSA-4096, rsa.h), which runs the exponentiation at 16 and 32 words, the second
// in 5 registers. A proof name is one launch line, so the variant gets its own file, the
// rsa_mul_webpki precedent.
#define CH_TRUST_WEBPKI 1
#include "rsa_ifma_sign_power_harness.c"
