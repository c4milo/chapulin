// The TRUST=webpki variant of the rsa_sign64_power proof: the same
// harness at the 512 bytes and 64 words CH_RSA_MODULUS_MAX and
// RSA_MONT64_WORDS_MAX resolve to under CH_TRUST_WEBPKI (RSA-4096,
// rsa.h). A proof name is one launch line, so the variant gets its own
// file, the rsa_mul_webpki precedent.
#define CH_TRUST_WEBPKI 1
#include "rsa_sign64_power_harness.c"
