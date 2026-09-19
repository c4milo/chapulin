// Proves: gcm_ghash reads and writes only inside its buffers and commits
// no undefined behavior, for any key, any associated data up to 256
// bytes and any ciphertext up to 256 bytes, at every length from zero to
// that bound on both arguments.
//
// This harness exists for the lengths quic_gcm_safety_harness.c cannot
// afford. That harness drives the whole module, so its formula carries
// five GHASH chains and it stops returning a verdict a few blocks up.
// This one drives the hash alone, so the same time budget buys sixteen
// blocks on each argument: SP 800-38D §6.4's block loop runs up to
// sixteen times here, where the whole-module formula runs it twice.
//
// The bound is still far below a QUIC packet. RFC 9001 §5.3 hands this
// AEAD a payload of up to about 1200 bytes, and no GHASH formula this
// tree has measured reaches that; test/quic_vectors.c and the Lean
// differential in test/diff_quic_test.c are what cover the longer
// lengths.
//
// The forward cipher is a contract stub (proof/quic_gcm_stubs.h), which
// states what the composition gives up and where the real cipher is
// proven.
#include "harness.h"

#include "quic_gcm_stubs.h"

#include "quic_gcm.c"

#ifndef CH_GHASH_AAD_MAX
#define CH_GHASH_AAD_MAX 256
#endif
#ifndef CH_GHASH_CT_MAX
#define CH_GHASH_CT_MAX 256
#endif

int main(void) {
    aes_public_key k;
    uint8_t aad[CH_GHASH_AAD_MAX];
    uint8_t ct[CH_GHASH_CT_MAX];
    uint8_t out[AES_BLOCK];

    // A key the constructors did not write is still a key this hash must
    // handle, so the schedules are havocked through their own type
    // rather than filled through a byte pointer.
    fill_nondet(k.key.round_keys, sizeof k.key.round_keys);
    fill_nondet(k.hp.round_keys, sizeof k.hp.round_keys);
    fill_nondet(k.iv, sizeof k.iv);
    fill_nondet(aad, sizeof aad);
    fill_nondet(ct, sizeof ct);

    size_t aad_len = nondet_size_t();
    size_t n = nondet_size_t();
    __CPROVER_assume(aad_len <= sizeof aad);
    __CPROVER_assume(n <= sizeof ct);

    gcm_ghash(&k, aad, aad_len, ct, n, out);
    return 0;
}
