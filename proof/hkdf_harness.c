// Proves: hmac_sha256 and hkdf_extract are memory-safe and UB-free for
// any key up to 96 bytes (crossing the hash-the-key path at 64) and any
// message up to 48 — plus the NULL-salt extract default. Expand and
// expand-label live in hkdf_expand_harness.c; splitting keeps each SAT
// instance small enough to solve in seconds instead of tens of minutes.
//
// Layered proof: sha256 is replaced by stubs asserting the contract its
// own proof established (valid context, readable input, writable output)
// and havocing results, so nothing here depends on hash values.
#include "harness.h"

#include "sha256.h"

void sha256_init(sha256 *s) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "init: ctx writable");
    fill_nondet((uint8_t *)s, sizeof *s);
}

void sha256_update(sha256 *s, const uint8_t *in, size_t n) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "update: ctx writable");
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "update: input readable");
}

void sha256_final(sha256 *s, uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(__CPROVER_w_ok(s, sizeof *s), "final: ctx writable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA256_LEN), "final: output writable");
    fill_nondet(out, SHA256_LEN);
}

void sha256_of(const uint8_t *in, size_t n, uint8_t out[SHA256_LEN]) {
    __CPROVER_assert(n == 0 || __CPROVER_r_ok(in, n), "of: input readable");
    __CPROVER_assert(__CPROVER_w_ok(out, SHA256_LEN), "of: output writable");
    fill_nondet(out, SHA256_LEN);
}

#include "hkdf.c"

int main(void) {
    uint8_t key[96];
    uint8_t msg[48];
    uint8_t prk[SHA256_LEN];
    size_t keylen = nondet_size_t();
    size_t msglen = nondet_size_t();
    __CPROVER_assume(keylen <= sizeof key);
    __CPROVER_assume(msglen <= sizeof msg);
    fill_nondet(key, sizeof key);
    fill_nondet(msg, sizeof msg);

    hmac_sha256(key, keylen, msg, msglen, prk);
    hkdf_extract(key, keylen, msg, msglen, prk);
    hkdf_extract(NULL, 0, msg, msglen, prk);
    return 0;
}
