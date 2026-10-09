// The TRUST=webpki variant of the rsa_ifma_product proof: the same harness
// under CH_TRUST_WEBPKI (RSA-4096, rsa.h), whose switch has a case for 8
// and 9 registers, at 51 and 58 words. A proof name is one launch line, so
// the variant gets its own file, the rsa_mul_webpki precedent.
#define CH_TRUST_WEBPKI 1
#include "rsa_ifma_product_harness.c"
