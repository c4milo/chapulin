// Proves: hmac_sha256, hkdf_extract, hkdf_expand, and hkdf_expand_label
// are memory-safe and UB-free — any key up to 160 bytes (crossing the
// hash-the-key path), any label 1..12, any context up to 32, any output
// up to 96 bytes (three blocks: the T(1) special case, the chained
// middle, and a partial tail — every structural path in the expand loop;
// the RFC 5869 255-block maximum adds only more of the middle case, and
// symbolic offsets over an 8 kB output array stall the solver).
//
// Layered proof: sha256 is replaced by stubs that assert the exact
// contract the standalone sha256 proof established (valid context,
// readable input, writable output) and havoc their results. hkdf is thus
// proven against the proven layer below, mlkem-native style; nothing
// here depends on hash values.
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
    uint8_t key[160];
    uint8_t msg[64];
    uint8_t prk[SHA256_LEN];
    static uint8_t out[3 * SHA256_LEN];
    size_t keylen = nondet_size_t();
    size_t msglen = nondet_size_t();
    __CPROVER_assume(keylen <= sizeof key);
    __CPROVER_assume(msglen <= sizeof msg);
    fill_nondet(key, sizeof key);
    fill_nondet(msg, sizeof msg);

    hmac_sha256(key, keylen, msg, msglen, prk);
    hkdf_extract(key, keylen, msg, msglen, prk);
    hkdf_extract(NULL, 0, msg, msglen, prk);

    size_t outlen = nondet_size_t();
    __CPROVER_assume(outlen >= 1 && outlen <= sizeof out);
    size_t infolen = nondet_size_t();
    __CPROVER_assume(infolen <= sizeof msg);
    hkdf_expand(prk, msg, infolen, out, outlen);

    // Any label the contract admits, not just the ones TLS uses today.
    char label[HKDF_LABEL_MAX + 1];
    size_t lab = nondet_size_t();
    __CPROVER_assume(lab >= 1 && lab <= HKDF_LABEL_MAX);
    for (size_t i = 0; i < lab; i++) {
        char c = (char)nondet_u8();
        __CPROVER_assume(c != 0);
        label[i] = c;
    }
    label[lab] = 0;
    size_t ctxlen = nondet_size_t();
    __CPROVER_assume(ctxlen <= SHA256_LEN);
    size_t outlen2 = nondet_size_t();
    __CPROVER_assume(outlen2 >= 1 && outlen2 <= 64);
    hkdf_expand_label(prk, label, msg, ctxlen, out, outlen2);
    return 0;
}
