// Proves: srv_cookie_harness.c's properties for a PROFILE=cnsa2 server's
// cookie (docs/decisions.md 162), whose MAC is HMAC-SHA-384, 48 bytes, so a
// cookie is 133 bytes and the open reads a 48-byte MAC. The launch line
// passes the profile server's defines. SHA-384 is the contract stub in
// harness.h beside SHA-256's, so HMAC-SHA-384 runs over digests CBMC picks
// freshly, and sha512_harness.c proves the hash.
#define CH_PROOF_STUB_SHA384
#include "srv_cookie_harness.c"
