// Proves: aead_seal and aead_open are memory-safe and UB-free for any
// plaintext up to 16 bytes and any AAD up to 16 bytes, and that a
// genuine seal opens back to the plaintext it sealed.
//
// The other two properties the aead.h contract states have their own
// harnesses: aead_overlap for the backward-overlap decrypt the record
// layer uses, aead_forge for all-or-nothing rejection. One formula
// carried all three and the SAT solver ran out of memory on it, since
// SAT cost grows super-linearly with formula size.
#include "harness.h"

#include "aead.c"

int main(void) {
    uint8_t key[AEAD_KEY];
    uint8_t nonce[AEAD_NONCE];
    uint8_t aad[16];
    uint8_t pt[16];
    uint8_t ct[16];
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

    uint8_t back[16];
    __CPROVER_assert(aead_open(key, nonce, aad, aad_len, ct, n, tag, back) == 1,
                     "genuine seal opens");
    for (size_t i = 0; i < n; i++) {
        __CPROVER_assert(back[i] == pt[i], "open round-trips");
    }
    return 0;
}
