// The pinned-key arm of the handshake driver proof: the server
// authenticates with a certificate whose signature the client checks
// against a provisioned raw public key, so Certificate,
// CertificateVerify and Finished are all in play. See
// handshake_harness.c for why the two arms are separate formulas.
#define CH_PROOF_PIN 1

#include "handshake_harness.c"
