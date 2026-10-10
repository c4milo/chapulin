// The 49-word TRUST=webpki variant of the rsa_avx2_chain proof: the same
// harness at 49 words under CH_TRUST_WEBPKI, 30 groups of 27-bit digits,
// the smallest word count the copies for 27-bit digits take. A proof name
// is one launch line, so the variant gets its own file, the
// rsa_mul_webpki precedent.
#define CH_TRUST_WEBPKI 1
#define CHAIN_WORDS 49
#include "rsa_avx2_chain_harness.c"
