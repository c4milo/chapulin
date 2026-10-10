// The 32-word variant of the rsa_avx2_chain proof: the same harness at 32
// words (RSA-2048), 19 groups of 28-bit digits, the smallest word count
// rsa_avx2_public takes. A proof name is one launch line, so the variant
// gets its own file, the rsa_mul_webpki precedent.
#define CHAIN_WORDS 32
#include "rsa_avx2_chain_harness.c"
