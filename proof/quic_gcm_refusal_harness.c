// Proves: gcm_open is all-or-nothing. For any tag at all, an open that
// returns 0 leaves every byte of the output buffer as the caller left
// it, checked against a sentinel the harness writes first. quic_gcm.h
// states that promise, and it is why the tag is computed over the
// ciphertext and compared before any plaintext byte is written.
//
// Nothing constrains the tag and nothing constrains the return value, so
// one formula carries the accepting arm and the refusing arm together.
// quic_gcm_forge_harness.c asks for the same promise by sealing first
// and then forcing the tag to differ from that seal's tag; that shape
// puts a whole gcm_seal in the formula and returns no verdict, which
// proof/run.sh records. Leaving the tag free gets the promise with one
// pipeline in the formula instead of two.
//
// The property is `rc != 0 || pt[i] == sentinel[i]`, which is vacuous if
// the refusing arm is unreachable. CH_GCM_REACH=1 replaces it with
// __CPROVER_assert(0) under __CPROVER_assume(rc == 0); that run must
// report VERIFICATION FAILED on that one property, and proof/run.sh
// records the measurement. CH_GCM_REACH=2 does the same for the
// accepting arm.
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
#ifndef CH_GCM_REACH
#define CH_GCM_REACH 0
#endif

int main(void) {
    aes_public_key k;
    uint8_t nonce[AES_IV];
    uint8_t aad[CH_GCM_AAD_MAX];
    uint8_t ct[CH_GCM_PT_MAX];
    uint8_t pt[CH_GCM_PT_MAX];
    uint8_t sentinel[CH_GCM_PT_MAX];
    uint8_t tag[GCM_TAG];

    fill_nondet(k.key.round_keys, sizeof k.key.round_keys);
    fill_nondet(k.hp.round_keys, sizeof k.hp.round_keys);
    fill_nondet(k.iv, sizeof k.iv);
    fill_nondet(nonce, sizeof nonce);
    fill_nondet(aad, sizeof aad);
    fill_nondet(ct, sizeof ct);
    fill_nondet(tag, sizeof tag);
    fill_nondet(sentinel, sizeof sentinel);

    size_t n = nondet_size_t();
    size_t aad_len = nondet_size_t();
    __CPROVER_assume(n <= sizeof ct);
    __CPROVER_assume(aad_len <= sizeof aad);

    for (size_t i = 0; i < sizeof pt; i++) {
        pt[i] = sentinel[i];
    }

    int rc = gcm_open(&k, nonce, aad, aad_len, ct, n, tag, pt);

#if CH_GCM_REACH == 1
    __CPROVER_assume(rc == 0);
    __CPROVER_assert(0, "refusing arm unreachable");
#elif CH_GCM_REACH == 2
    __CPROVER_assume(rc == 1);
    __CPROVER_assert(0, "accepting arm unreachable");
#else
    for (size_t i = 0; i < sizeof pt; i++) {
        __CPROVER_assert(rc != 0 || pt[i] == sentinel[i], "failed open writes nothing");
    }
#endif
    return 0;
}
