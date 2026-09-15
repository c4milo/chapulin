// The TRUST=webpki variant of the rsa_pkcs1 proof: the same harness at
// the 512-byte modulus CH_RSA_MODULUS_MAX resolves to under
// CH_TRUST_WEBPKI (RSA-4096, rsa.h). A proof name is one launch line, so
// the variant gets its own file, the pem_ecdsa precedent.
#define CH_TRUST_WEBPKI 1
#include "rsa_pkcs1_harness.c"
