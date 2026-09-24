// The SHA-384 arm of the hmac and extract proof: hmac_sha384 and the
// dispatcher's second arm compile only under CH_HASH_SHA384, which a
// SUITE=aesgcm object defines. See hkdf_harness.c for the domains.
#define CH_HASH_SHA384
#define CH_PROOF_STUB_SHA384
#include "hkdf_harness.c"
