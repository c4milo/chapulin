// Proves: hmac_sha256 and hkdf_extract are memory-safe and UB-free for
// any key up to one hash block plus 32 bytes (crossing the hash-the-key
// path at the block size) and any message up to 48, plus the NULL-salt
// extract default. Expand and expand-label live in hkdf_expand_harness.c;
// splitting keeps each SAT instance small enough to solve in seconds
// instead of tens of minutes.
//
// hkdf384_harness.c compiles this file under CH_HASH_SHA384. There the
// block is SHA-512's 128 bytes, so the key reaches 160; hmac_sha384 is
// called directly; and extract takes a hash_len free over the two values
// the dispatcher in hmac accepts, so both of its arms are under proof.
//
// Layered proof: the hashes are replaced by stubs asserting the contract
// their own proofs established (valid context, readable input, writable
// output) and havocing results, so nothing here depends on hash values.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include "sha256.h"

#include "hkdf.c"

#ifdef CH_HASH_SHA384
#define PROOF_BLOCK SHA512_BLOCK
#else
#define PROOF_BLOCK SHA256_BLOCK
#endif

int main(void) {
    uint8_t key[PROOF_BLOCK + 32];
    uint8_t msg[48];
    uint8_t prk[HKDF_HASH_MAX];
    size_t key_len = nondet_size_t();
    size_t msg_len = nondet_size_t();
    __CPROVER_assume(key_len <= sizeof key);
    __CPROVER_assume(msg_len <= sizeof msg);
    fill_nondet(key, sizeof key);
    fill_nondet(msg, sizeof msg);

    hmac_sha256(key, key_len, msg, msg_len, prk);
#ifdef CH_HASH_SHA384
    hmac_sha384(key, key_len, msg, msg_len, prk);
    size_t hash_len = nondet_size_t();
    __CPROVER_assume(hash_len == SHA256_LEN || hash_len == SHA384_LEN);
#else
    size_t hash_len = SHA256_LEN;
#endif
    hkdf_extract(hash_len, key, key_len, msg, msg_len, prk);
    hkdf_extract(hash_len, NULL, 0, msg, msg_len, prk);
    return 0;
}
