// The PSK arm of the handshake driver proof: the server authenticates
// with the pre-shared key, so RFC 9846 §2.2 sends no certificate
// flight. See handshake_harness.c for why the two arms are separate
// formulas.
#define CH_PROOF_PSK 1

#include "handshake_harness.c"
