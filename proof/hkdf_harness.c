// Proves: hmac_sha256 and hkdf_extract are memory-safe and UB-free for
// any key up to 96 bytes (crossing the hash-the-key path at 64) and any
// message up to 48 — plus the NULL-salt extract default. Expand and
// expand-label live in hkdf_expand_harness.c; splitting keeps each SAT
// instance small enough to solve in seconds instead of tens of minutes.
//
// Layered proof: sha256 is replaced by stubs asserting the contract its
// own proof established (valid context, readable input, writable output)
// and havocing results, so nothing here depends on hash values.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include "sha256.h"

#include "hkdf.c"

int main(void) {
    uint8_t key[96];
    uint8_t msg[48];
    uint8_t prk[SHA256_LEN];
    size_t key_len = nondet_size_t();
    size_t msg_len = nondet_size_t();
    __CPROVER_assume(key_len <= sizeof key);
    __CPROVER_assume(msg_len <= sizeof msg);
    fill_nondet(key, sizeof key);
    fill_nondet(msg, sizeof msg);

    hmac_sha256(key, key_len, msg, msg_len, prk);
    hkdf_extract(key, key_len, msg, msg_len, prk);
    hkdf_extract(NULL, 0, msg, msg_len, prk);
    return 0;
}
