// Proves hybrid_secret_harness.c's claims for kem_secret under
// PROFILE=cnsa2 (docs/decisions.md 151): its launch line passes the
// profile's defines, so the function decapsulates an ML-KEM-1024
// ciphertext into the 32-byte ikm, runs no x25519 and returns CH_OK for
// any stored seed and any 1568-byte ciphertext, and both exits leave
// the seed zero. The ML-KEM stubs assert the K = 4 lengths.
#ifndef CH_PROFILE_CNSA2
#error "kem_secret_cnsa2_harness proves the -DCH_PROFILE_CNSA2 build"
#endif
#include "hybrid_secret_harness.c"
