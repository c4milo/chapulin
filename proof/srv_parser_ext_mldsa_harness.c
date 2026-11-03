// Proves: srv_parser_ext_harness.c's properties under CH_SIGN_MLDSA outside
// PROFILE=cnsa2, the define every host server object takes, where the
// signature_algorithms reader sets the mldsa87 bit beside the ECDSA and RSA
// ones (docs/decisions.md 180).
#include "srv_parser_ext_harness.c"
