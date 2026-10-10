// The TRUST=webpki variant of the rsa_ifma_sign_setup proof: the same harness under
// CH_TRUST_WEBPKI (RSA-4096, rsa.h), which runs every word count from 16 to 32.
// A proof name is one launch line, so the variant gets its own file, the
// rsa_mul_webpki precedent.
#define CH_TRUST_WEBPKI 1
#include "rsa_ifma_sign_setup_harness.c"
