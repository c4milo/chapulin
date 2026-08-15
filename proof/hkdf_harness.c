// Proves: hmac_sha256, hkdf_extract, hkdf_expand, and hkdf_expand_label
// are memory-safe and UB-free across their full contracts — any key up to
// 131 bytes (crossing the hash-the-key path), any label length 1..12, any
// context up to 32 bytes, any output up to 64 bytes.
#include "harness.h"

#include "hkdf.c"

int main(void) {
    uint8_t key[131];
    uint8_t msg[64];
    uint8_t out[64];
    uint8_t prk[SHA256_LEN];
    size_t keylen = nondet_size_t();
    size_t msglen = nondet_size_t();
    __CPROVER_assume(keylen <= sizeof key);
    __CPROVER_assume(msglen <= sizeof msg);
    fill_nondet(key, keylen);
    fill_nondet(msg, msglen);

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
    hkdf_expand_label(prk, label, msg, ctxlen, out, outlen);
    return 0;
}
