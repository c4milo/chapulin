// The rsa_avx2_sums proof of square_28, the square for digits of 28 bits, at
// 2 groups. A proof name is one launch line, so each product gets its own
// file, the rsa_mul_webpki precedent.
#define SUMS_BITS 28
#define SUMS_GROUPS 2
#define SUMS_SQUARE 1
#include "rsa_avx2_sums_harness.c"
