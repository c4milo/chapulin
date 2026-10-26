// The decomposition variant of the mldsa_sign_coefficient proof: the same
// harness with ct_widemul_s resolved to ct.h's 16x16 decomposition, the
// multiply a host object runs for a session without
// CH_CPU_CONSTANT_TIME_MULTIPLY and the one the signer runs in this commit
// (docs/decisions.md 159). CH_CPU_CONSTANT_TIME_MULTIPLY's native arm is
// mldsa_sign_coefficient. CH_CT_WIDEMUL wins over run.sh's
// -DCH_NATIVE_WIDEMUL (ct.h), as in x25519_mul_ct_harness.c. A proof name
// is one launch line, so the variant gets its own file.
#define CH_CT_WIDEMUL 1
#include "mldsa_sign_coefficient_harness.c"
