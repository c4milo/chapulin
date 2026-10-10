// The TRUST=webpki variant of the rsa_avx2_chain proof: the same harness
// at the 64 words and 512 bytes the bounds resolve to under CH_TRUST_WEBPKI
// (RSA-4096, rsa.h), 38 groups of 27-bit digits, the most rsa_avx2_public
// takes. A proof name is one launch line, so the variant gets its own
// file, the rsa_mul_webpki precedent.
#define CH_TRUST_WEBPKI 1
#include "rsa_avx2_chain_harness.c"
