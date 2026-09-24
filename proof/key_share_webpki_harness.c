// The TRUST=webpki variant of the key_share proof: the same harness over
// the arm CH_KEX_TWO_GROUPS widens (docs/decisions.md entry 53), where a
// ServerHello may select x25519 with a 32-byte share beside the hybrid
// one. The launch line passes -DCH_TRUST_WEBPKI so buf.c and this file
// see the same build; cfg.h refuses -DCH_KEX_PQ beside it. A proof name
// is one launch line, so the variant gets its own file, the
// hello_build_webpki precedent.
#ifndef CH_TRUST_WEBPKI
#error "key_share_webpki proves the two-group arm; its launch line must pass -DCH_TRUST_WEBPKI"
#endif
#include "key_share_harness.c"
