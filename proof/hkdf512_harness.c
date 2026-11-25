// The SHA-512 arm of the hmac and extract proof: hmac_sha512 and the
// dispatcher's third arm compile only under CH_HASH, which a HASH=on
// object defines (docs/decisions.md 246). hmac_sha384 compiles there too,
// so this file proves both arms. See hkdf_harness.c for the domains.
#define CH_HASH
#define CH_PROOF_STUB_SHA384
#define CH_PROOF_STUB_SHA512
#include "hkdf_harness.c"
