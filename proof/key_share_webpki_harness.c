// The KEX=pq TRUST=webpki variant of the key_share proof: the same
// harness over the arm CH_KEX_TWO_GROUPS widens (docs/decisions.md entry
// 39), where a HelloRetryRequest may name x25519 and a ServerHello may
// select it with a 32-byte share. The launch line passes both defines so
// buf.c and this file see the same build. A proof name is one launch
// line, so the variant gets its own file, the hello_build_webpki
// precedent.
#if !defined(CH_TRUST_WEBPKI) || !defined(CH_KEX_PQ)
#error                                                                                             \
    "key_share_webpki proves the two-group arm; its launch line must pass -DCH_KEX_PQ -DCH_TRUST_WEBPKI"
#endif
#include "key_share_harness.c"
