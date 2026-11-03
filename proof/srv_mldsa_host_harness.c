// Proves proof/srv_mldsa_harness.c's claims for srv_mldsa.c in a host
// server outside PROFILE=cnsa2, where it is the third identity beside the
// ECDSA and RSA ones (docs/decisions.md 180): its launch line passes a host
// server's defines, under which srv_mldsa.c defines srv_mldsa.h's four
// calls and none of srv_auth.h's.
#ifdef CH_PROFILE_CNSA2
#error "srv_mldsa_host_harness proves the server outside PROFILE=cnsa2"
#endif
#include "srv_mldsa_harness.c"
