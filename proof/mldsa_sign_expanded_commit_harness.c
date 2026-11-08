// Proves: mlds_commit in a host object (-DCH_CPU_RUNTIME, docs/decisions.md
// 191) is memory-safe and UB-free with the signed-overflow check on, when
// it reads the rows of A from st->ex, over every state, mu, rho'', kappa
// the loop passes and cpu value. Every value it decomposes is in [0, q):
// each row comes frozen from stored_row, the real one, over the contracts
// of the products. proof/mldsa_sign_expanded_harness.c states the stubs.
#define EXPANDED_COMMIT
#include "mldsa_sign_expanded_harness.c"
