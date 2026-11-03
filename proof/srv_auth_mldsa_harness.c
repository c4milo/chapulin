// Proves proof/srv_auth_harness.c's claims for srv_auth.c in an object
// that signs ML-DSA-87 (CH_SIGN_MLDSA), every host server
// (docs/decisions.md 180), and the two facts that harness states for the
// mldsa87 slot: the order of srv_select_sigalg and the refusal of
// srv_sign_certificate_verify.
#ifndef CH_SIGN_MLDSA
#error "srv_auth_mldsa_harness proves the -DCH_SIGN_MLDSA build"
#endif
#include "srv_auth_harness.c"
