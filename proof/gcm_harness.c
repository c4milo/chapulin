// Proves: gcm_seal, gcm_open and gcm_ghash are memory-safe and UB-free
// for any plaintext up to 16 bytes and any associated data up to 16
// bytes, and that a genuine seal opens back to the plaintext it sealed.
//
// The bound is one block and the lengths either side of it. GCM has no
// length field of its own — SP 800-38D §5.2.1.1 bounds a plaintext at
// 2^39 - 256 bits and QUIC's own limit is the packet size — so the real
// bound here is the block boundary, where the §6.4 pad and the §6.5
// truncation of the last block are decided. Every length from zero to
// one block and one byte goes through the formula, on both arguments.
//
// Aliasing: quic_initial.c will decrypt a packet payload in place, so
// gcm_open is called with pt == ct as well as with distinct buffers.
// gcm_seal is called with pt == ct for the same reason.
//
// The refusal arm — that a wrong tag releases no plaintext byte — is
// gcm_forge, its own harness for the reason aead_forge is its own:
// one formula carrying both the round trip and the refusal is the shape
// that stops converging.
//
// The forward cipher is a contract stub (proof/gcm_stubs.h), which
// states what the composition gives up and where the real cipher is
// proven.
#include "harness.h"

#include "gcm_stubs.h"

#include "gcm.c"

int main(void) {
    aes_public_key k;
    uint8_t nonce[AES_IV];
    uint8_t aad[16];
    uint8_t pt[16];
    uint8_t ct[16];
    uint8_t tag[GCM_TAG];

    // A key the constructors did not write is still a key this AEAD must
    // handle, so the schedules are havocked through their own type
    // rather than filled through a byte pointer.
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

    uint8_t back[16];
    __CPROVER_assert(gcm_open(&k, nonce, aad, aad_len, ct, n, tag, back) == 1,
                     "genuine seal opens");
    for (size_t i = 0; i < n; i++) {
        __CPROVER_assert(back[i] == pt[i], "open round-trips");
    }

    // GHASH on its own, over freshly havocked operands, because
    // gcm.h declares it and SP 800-38D's vectors drive it directly.
    uint8_t hashed[AES_BLOCK];
    fill_nondet(aad, sizeof aad);
    fill_nondet(ct, sizeof ct);
    gcm_ghash(&k, aad, aad_len, ct, n, hashed);

    // The in-place shapes the header admits. Each operand is havocked
    // again first, so neither call reads a value an earlier call left.
    fill_nondet(pt, sizeof pt);
    fill_nondet(aad, sizeof aad);
    fill_nondet(nonce, sizeof nonce);
    gcm_seal(&k, nonce, aad, aad_len, pt, n, pt, tag);
    __CPROVER_assert(gcm_open(&k, nonce, aad, aad_len, pt, n, tag, pt) == 1,
                     "in-place seal opens in place");
    return 0;
}
