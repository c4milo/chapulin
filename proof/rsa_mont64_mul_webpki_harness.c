// The TRUST=webpki variant of the rsa_mont64_mul proof: the same harness
// at the 64 words RSA_MONT64_WORDS_MAX resolves to under CH_TRUST_WEBPKI
// (RSA-4096, rsa.h). A proof name is one launch line, so the variant gets
// its own file, the rsa_mul_webpki precedent.
#define CH_TRUST_WEBPKI 1
#include "rsa_mont64_mul_harness.c"
