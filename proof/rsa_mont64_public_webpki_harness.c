// The TRUST=webpki variant of the rsa_mont64_public proof: the same
// harness at the 64 limbs and 512 bytes the bounds resolve to under
// CH_TRUST_WEBPKI (RSA-4096, rsa.h). A proof name is one launch line, so
// the variant gets its own file, the rsa_mul_webpki precedent.
#define CH_TRUST_WEBPKI 1
#include "rsa_mont64_public_harness.c"
