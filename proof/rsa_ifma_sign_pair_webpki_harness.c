// The TRUST=webpki variant of the rsa_ifma_sign_pair proof: the same harness under
// CH_TRUST_WEBPKI (RSA-4096, rsa.h), which runs the copy of the pair for 5 registers, at 32 words,
// whose case only that build's switch holds. A proof name is one launch line, so the variant gets
// its own file, the rsa_mul_webpki precedent.
#define CH_TRUST_WEBPKI 1
#include "rsa_ifma_sign_pair_harness.c"
