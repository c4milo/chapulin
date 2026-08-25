// Proves: aead_seal encrypts correctly with the plaintext and
// ciphertext one buffer (pt == ct) — the shape rec_seal ships on every
// outgoing record — and aead_open decrypts correctly at the same full
// overlap, both granted by the aead.h contract. Sealing in place then
// opening in place must hand back the bytes sealed.
//
// Its own formula, like aead_overlap: SAT time and memory grow
// super-linearly with formula size, so one aliasing shape per harness
// converges where a combined formula does not. Together with aead,
// aead_forge, and aead_overlap this covers every overlap the contract
// grants and a shipped caller uses.
#include "harness.h"

#include "aead.c"

int main(void) {
    uint8_t key[AEAD_KEY];
    uint8_t nonce[AEAD_NONCE];
    uint8_t aad[16];
    uint8_t buf[16];
    uint8_t copy[16];
    fill_nondet(key, sizeof key);
    fill_nondet(nonce, sizeof nonce);
    fill_nondet(aad, sizeof aad);
    fill_nondet(buf, sizeof buf);

    size_t n = nondet_size_t();
    size_t aad_len = nondet_size_t();
    __CPROVER_assume(n >= 1 && n <= sizeof buf);
    __CPROVER_assume(aad_len <= sizeof aad);
    for (size_t i = 0; i < n; i++) {
        copy[i] = buf[i];
    }

    uint8_t tag[AEAD_TAG];
    aead_seal(key, nonce, aad, aad_len, buf, n, buf, tag);
    __CPROVER_assert(aead_open(key, nonce, aad, aad_len, buf, n, tag, buf) == 1,
                     "in-place open succeeds");
    for (size_t i = 0; i < n; i++) {
        __CPROVER_assert(buf[i] == copy[i], "in-place seal then open round-trips");
    }
    return 0;
}
