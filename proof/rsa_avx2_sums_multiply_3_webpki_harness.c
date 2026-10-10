// The rsa_avx2_sums proof of multiply_27, the multiplication for digits of
// 27 bits, at 3 groups, under CH_TRUST_WEBPKI, the one build that compiles
// it. A proof name is one launch line, so each product gets its own file,
// the rsa_mul_webpki precedent.
#define CH_TRUST_WEBPKI 1
#define SUMS_BITS 27
#define SUMS_GROUPS 3
#define SUMS_SQUARE 0
#include "rsa_avx2_sums_harness.c"
