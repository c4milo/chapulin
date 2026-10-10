// The rsa_avx2_sums proof of multiply_28, the multiplication for digits of
// 28 bits, at 3 groups. A proof name is one launch line, so each product
// gets its own file, the rsa_mul_webpki precedent.
#define SUMS_BITS 28
#define SUMS_GROUPS 3
#define SUMS_SQUARE 0
#include "rsa_avx2_sums_harness.c"
