// The key generation half of the mldsa_signer proof: the same harness with
// SIGNER_KEYGEN, so its main runs mldsa87_keygen alone. A proof name is one
// launch line, so the half gets its own file.
#define SIGNER_KEYGEN 1
#include "mldsa_signer_harness.c"
