// The 5-register variant of the rsa_ifma_public proof: the same harness at
// 32 words (RSA-2048), the only word count 5 registers hold and the
// smallest rsa_ifma_public takes. A proof name is one launch line, so the
// variant gets its own file, the rsa_mul_webpki precedent.
#define PUBLIC_WORDS 32
#include "rsa_ifma_public_harness.c"
