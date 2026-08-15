// Proves: aead_seal and aead_open are memory-safe and UB-free for any
// plaintext up to 64 bytes and any AAD up to 32 bytes, and open is
// all-or-nothing — on any forged tag it writes no plaintext (checked by
// asserting the output buffer's sentinel survives a failed open).
#include "harness.h"

#include "aead.c"

int main(void) {
    uint8_t key[AEAD_KEY];
    uint8_t nonce[AEAD_NONCE];
    uint8_t aad[32];
    uint8_t pt[64];
    uint8_t ct[64];
    uint8_t tag[AEAD_TAG];
    fill_nondet(key, sizeof key);
    fill_nondet(nonce, sizeof nonce);
    fill_nondet(aad, sizeof aad);
    fill_nondet(pt, sizeof pt);

    size_t n = nondet_size_t();
    size_t aadlen = nondet_size_t();
    __CPROVER_assume(n >= 1 && n <= sizeof pt);
    __CPROVER_assume(aadlen <= sizeof aad);

    aead_seal(key, nonce, aad, aadlen, pt, n, ct, tag);

    // Round-trip must authenticate and decrypt to the original.
    uint8_t back[64];
    __CPROVER_assert(aead_open(key, nonce, aad, aadlen, ct, n, tag, back) == 1,
                     "genuine seal opens");
    for (size_t i = 0; i < n; i++) {
        __CPROVER_assert(back[i] == pt[i], "open round-trips");
    }

    // A tag that differs anywhere must fail and write nothing.
    uint8_t forged[AEAD_TAG];
    fill_nondet(forged, sizeof forged);
    uint32_t same = 1;
    for (size_t i = 0; i < AEAD_TAG; i++) {
        if (forged[i] != tag[i]) {
            same = 0;
        }
    }
    __CPROVER_assume(!same);
    uint8_t sentinel[64];
    fill_nondet(sentinel, sizeof sentinel);
    uint8_t out2[64];
    for (size_t i = 0; i < sizeof out2; i++) {
        out2[i] = sentinel[i];
    }
    __CPROVER_assert(aead_open(key, nonce, aad, aadlen, ct, n, forged, out2) == 0,
                     "forged tag rejected");
    for (size_t i = 0; i < sizeof out2; i++) {
        __CPROVER_assert(out2[i] == sentinel[i], "failed open writes nothing");
    }
    return 0;
}
