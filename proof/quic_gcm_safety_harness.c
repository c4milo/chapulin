// Proves: gcm_seal, gcm_open and gcm_ghash read and write only inside
// their buffers and commit no undefined behavior, for any plaintext up
// to 16 bytes, any associated data up to 16 bytes, any key schedule and
// any nonce, in both aliasing shapes quic_gcm.h admits.
//
// The bound is one block and the lengths either side of it. GCM has no
// length field of its own — SP 800-38D §5.2.1.1 bounds a plaintext at
// 2^39 - 256 bits and QUIC's own limit is the packet size — so the real
// bound here is the block boundary, where the §6.4 pad and the §6.5
// truncation of the last block are decided. Every length from zero to
// one block goes through the formula, on both arguments.
//
// Aliasing: quic_initial.c decrypts a packet payload in place, so
// gcm_open is called with pt == ct as well as with distinct buffers, and
// gcm_seal is called with pt == ct for the same reason.
//
// This harness carries no functional assert. The round trip — that a
// genuine seal opens back to the plaintext it sealed — is
// quic_gcm_harness.c, which has no launch line because its formula
// returns no verdict; proof/run.sh records that measurement. What the
// round trip is not proving here, the RFC 9001 Appendix A and SP
// 800-38D vectors in test/quic_vectors.c and the Lean differential in
// test/diff_quic_test.c cover instead.
//
// The forward cipher is a contract stub (proof/quic_gcm_stubs.h), which
// states what the composition gives up and where the real cipher is
// proven.
#include "harness.h"

#include "quic_gcm_stubs.h"

#include "quic_gcm.c"

#ifndef CH_GCM_PT_MAX
#define CH_GCM_PT_MAX 16
#endif
#ifndef CH_GCM_AAD_MAX
#define CH_GCM_AAD_MAX 16
#endif

int main(void) {
    aes_public_key k;
    uint8_t nonce[AES_IV];
    uint8_t aad[CH_GCM_AAD_MAX];
    uint8_t pt[CH_GCM_PT_MAX];
    uint8_t ct[CH_GCM_PT_MAX];
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

    uint8_t back[CH_GCM_PT_MAX];
    (void)gcm_open(&k, nonce, aad, aad_len, ct, n, tag, back);

    // GHASH on its own, over freshly havocked operands, because
    // quic_gcm.h declares it and SP 800-38D's vectors drive it directly.
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
    (void)gcm_open(&k, nonce, aad, aad_len, pt, n, tag, pt);
    return 0;
}
