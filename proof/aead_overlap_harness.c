// Proves: aead_open decrypts correctly when the plaintext buffer sits
// REC_HDR bytes below the ciphertext — the backward overlap the aead.h
// contract grants and the record layer relies on to decrypt in place.
//
// Split out of aead_harness.c: that formula sealed and opened five
// times over, and the SAT solver ran out of memory on it. SAT time and
// memory grow super-linearly with formula size, so one property per
// harness converges where all three together do not. Together with
// aead and aead_forge this covers what the single harness asserted.
#include "harness.h"

#include "aead.c"

int main(void) {
    uint8_t key[AEAD_KEY];
    uint8_t nonce[AEAD_NONCE];
    uint8_t aad[32];
    uint8_t pt[64];
    fill_nondet(key, sizeof key);
    fill_nondet(nonce, sizeof nonce);
    fill_nondet(aad, sizeof aad);
    fill_nondet(pt, sizeof pt);

    size_t n = nondet_size_t();
    size_t aad_len = nondet_size_t();
    __CPROVER_assume(n >= 1 && n <= sizeof pt);
    __CPROVER_assume(aad_len <= sizeof aad);

    uint8_t frame[5 + 64];
    uint8_t tag[AEAD_TAG];
    aead_seal(key, nonce, aad, aad_len, pt, n, frame + 5, tag);
    __CPROVER_assert(aead_open(key, nonce, aad, aad_len, frame + 5, n, tag, frame) == 1,
                     "backward-overlap open succeeds");
    for (size_t i = 0; i < n; i++) {
        __CPROVER_assert(frame[i] == pt[i], "backward-overlap open round-trips");
    }
    return 0;
}
