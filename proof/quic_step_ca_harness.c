// The CA-mode arm of the step table proof: hsa_epoch_commit runs in
// the Finished step there and in no other mode, and that build's
// handshake_state is larger, so the wipe the step makes has its own
// bound. See quic_step_harness.c for what the leg proves.
#define CH_TRUST_CA_SELECTOR 1

#include "quic_step_harness.c"
