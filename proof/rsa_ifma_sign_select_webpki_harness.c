// The TRUST=webpki variant of the rsa_ifma_sign_select proof: the same harness under
// CH_TRUST_WEBPKI (RSA-4096, rsa.h), which runs the read at 5 registers, the most a prime of that
// build takes. A proof name is one launch line, so the variant gets its own file, the
// rsa_mul_webpki precedent.
#define CH_TRUST_WEBPKI 1
#include "rsa_ifma_sign_select_harness.c"
