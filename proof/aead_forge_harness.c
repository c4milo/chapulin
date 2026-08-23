// Proves: aead_open is all-or-nothing. On any tag that differs from the
// genuine one it returns 0 and writes no plaintext, checked by asserting
// the output buffer's sentinel survives the failed open.
//
// Split out of aead_harness.c; see aead_overlap_harness.c for why.
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
    size_t aad_len = nondet_size_t();
    __CPROVER_assume(n >= 1 && n <= sizeof pt);
    __CPROVER_assume(aad_len <= sizeof aad);

    aead_seal(key, nonce, aad, aad_len, pt, n, ct, tag);

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
    uint8_t out[64];
    for (size_t i = 0; i < sizeof out; i++) {
        out[i] = sentinel[i];
    }
    __CPROVER_assert(aead_open(key, nonce, aad, aad_len, ct, n, forged, out) == 0,
                     "forged tag rejected");
    for (size_t i = 0; i < sizeof out; i++) {
        __CPROVER_assert(out[i] == sentinel[i], "failed open writes nothing");
    }
    return 0;
}
