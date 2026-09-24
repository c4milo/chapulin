// The SHA-384 arm of the key schedule proof: keysched.c's SHA-384
// empty-transcript hash and the dispatch in hkdf.c compile only under
// CH_HASH_SHA384, which a SUITE=aesgcm object defines, and every buffer
// the schedule touches is 48 bytes there. See keysched_harness.c.
#define CH_HASH_SHA384
#define CH_PROOF_STUB_SHA384
#include "keysched_harness.c"
