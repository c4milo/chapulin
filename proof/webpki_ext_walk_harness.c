// The whole-walk part of the webpki_ext proof: webpki_read_extensions
// over a field of at most CH_PROOF_EXT_LEN bytes, the bound the launch
// line records, read from its first byte with err clear. The reader
// does not start in any state here: that formula returns no verdict at
// this bound, which webpki_ext_harness.c's Bit 16 comment and README.md
// both record. A proof name is one launch line, so the part gets its
// own file, the pem_ecdsa precedent; the body and what it proves are in
// webpki_ext_harness.c.
#define CH_PROOF_PARTS 16
#include "webpki_ext_harness.c"
