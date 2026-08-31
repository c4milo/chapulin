// The ECDSA-build variant of the x509ca proof: same harness, the other
// SPKI arm and the smaller CH_X509_MAX that CH_PEM_MAX derives from.
// A proof name is one launch line, so the variant gets its own file,
// the x509der_ecdsa precedent.
#define CH_PIN_ECDSA 1
#include "x509ca_harness.c"
