// Proves: gcm_open is all-or-nothing. On any tag that differs from the
// genuine one it returns 0 and writes no plaintext, checked by asserting
// that the output buffer's sentinel survives the failed open. quic_gcm.h
// states that promise, and it is why the tag is computed over the
// ciphertext before any plaintext byte is written.
//
// Split out of quic_gcm_harness.c, for the reason aead_forge is split
// out of aead_harness.c: one formula carrying the round trip and the
// refusal together is the shape that stops converging
// (https://github.com/c4milo/chapulin/issues/56).
//
// The forward cipher is a contract stub (proof/quic_gcm_stubs.h), which
// states what the composition gives up and where the real cipher is
// proven.
#include "harness.h"

#include "quic_gcm_stubs.h"

#include "quic_gcm.c"

int main(void) {
    aes_public_key k;
    uint8_t nonce[AES_IV];
    uint8_t aad[16];
    uint8_t pt[16];
    uint8_t ct[16];
    uint8_t tag[GCM_TAG];

    // The key is havocked through its own type rather than filled
    // through a byte pointer, and a key the constructors did not write
    // is still a key this AEAD must refuse a wrong tag under.
    fill_nondet(k.key.round_keys, sizeof k.key.round_keys);
    fill_nondet(k.hp.round_keys, sizeof k.hp.round_keys);
    fill_nondet(k.iv, sizeof k.iv);
    fill_nondet(nonce, sizeof nonce);
    fill_nondet(aad, sizeof aad);
    fill_nondet(pt, sizeof pt);

    size_t n = nondet_size_t();
    size_t aad_len = nondet_size_t();
    __CPROVER_assume(n <= sizeof pt);
    __CPROVER_assume(aad_len <= sizeof aad);

    gcm_seal(&k, nonce, aad, aad_len, pt, n, ct, tag);

    // Any tag at all, as long as it is not the genuine one. An
    // unconstrained tag proves the refusal for every wrong value rather
    // than for one bit flip.
    uint8_t forged[GCM_TAG];
    fill_nondet(forged, sizeof forged);
    uint32_t same = 1;
    for (size_t i = 0; i < GCM_TAG; i++) {
        if (forged[i] != tag[i]) {
            same = 0;
        }
    }
    __CPROVER_assume(!same);

    uint8_t sentinel[16];
    fill_nondet(sentinel, sizeof sentinel);
    uint8_t out[16];
    for (size_t i = 0; i < sizeof out; i++) {
        out[i] = sentinel[i];
    }
    __CPROVER_assert(gcm_open(&k, nonce, aad, aad_len, ct, n, forged, out) == 0,
                     "forged tag rejected");
    for (size_t i = 0; i < sizeof out; i++) {
        __CPROVER_assert(out[i] == sentinel[i], "failed open writes nothing");
    }
    return 0;
}
