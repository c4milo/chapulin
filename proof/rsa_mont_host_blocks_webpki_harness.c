// The TRUST=webpki variant of the rsa_mont_host_blocks proof: the same
// harness at the 64 words and 512 bytes the bounds resolve to under
// CH_TRUST_WEBPKI (RSA-4096, rsa.h).
#define CH_TRUST_WEBPKI 1
#include "rsa_mont_host_blocks_harness.c"
