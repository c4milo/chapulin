// The TRUST=webpki variant of the rsa_mont_power_avx2 proof: the same
// harness at the 64 words the bounds resolve to under CH_TRUST_WEBPKI
// (RSA-4096), the most rsa_avx2_public takes. A proof name is one launch
// line, so the variant gets its own file, the rsa_mul_webpki precedent.
#define CH_TRUST_WEBPKI 1
#include "rsa_mont_power_avx2_harness.c"
