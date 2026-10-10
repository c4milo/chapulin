// The TRUST=webpki variant of the rsa_avx2_number proof: the same harness
// under CH_TRUST_WEBPKI, at every word count from 32 to 64, where the
// conversions also take digits of 27 bits. A proof name is one launch
// line, so the variant gets its own file, the rsa_mul_webpki precedent.
#define CH_TRUST_WEBPKI 1
#include "rsa_avx2_number_harness.c"
