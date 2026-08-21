// The ECDSA-build variant of the walker proof. This variant carries
// the FULL two-entry bound (256 covers two max ECDSA certificates);
// the RSA variant's full formula does not converge, so its launch
// line proves the single-max-entry bound in the slow tier and the
// two-entry walk rests on this proof — the walker code is identical
// outside the SPKI arm.
#define CH_PIN_ECDSA 1
#include "x509parse_harness.c"
