// gcm_avx512.h's two entries: the kernel for the key size, the wipe of the stack it used, and the
// wipe of the vector registers it used. The functions here carry no target attribute, so they
// hold no AVX-512 instruction; avx512_wipe.c holds the block of assembly that clears the
// registers.
#include "gcm_avx512.h"

#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
// The entries compile in a host object on x86-64, and in a proof unit that defines
// CH_GCM_AVX512_MODEL, which compiles them over contract stubs of the kernel and of
// avx512_wipe_registers on any target (proof/gcm_avx512_wipe_harness.c).
#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_GCM_AVX512_MODEL))

#include <stdint.h>

#include "avx512_wipe.h"
#include "ct.h"
#include "gcm_avx512_kernel.h"

// The wipe of the stack below an entry, in p256_wide_wipe.c's form. Its frame is the array.
// ct_wipe is compiled apart from it and takes the array's address, so the compiler keeps the
// array in memory and cannot delete the call.
static void wipe_frame(void) {
    uint8_t below[GCM_AVX512_BELOW_LEN];
    ct_wipe(below, sizeof below);
}

// The entries call wipe_frame through this pointer, for the reason ct_wipe.c calls memset through
// one: the pointer is a volatile object, so the compiler cannot tell which function the call
// runs and cannot compile it into an entry, where the array would join the entry's frame and lie
// above the kernel's frames it is there to wipe.
static void (*const volatile wipe_frame_call)(void) = wipe_frame;

void gcm_seal_avx512(const uint8_t *round_keys, size_t rounds, const uint8_t nonce[AES_IV],
                     const uint8_t *aad, size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                     uint8_t tag[AES_BLOCK]) {
#ifdef CH_AES_256
    // The round count is the suite's, so this branch reads a public value.
    if (rounds == AES_256_ROUNDS) {
        gcm_avx512_seal_256(round_keys, nonce, aad, aad_len, pt, n, ct, tag);
    } else {
        gcm_avx512_seal_128(round_keys, nonce, aad, aad_len, pt, n, ct, tag);
    }
#else
    (void)rounds;
    gcm_avx512_seal_128(round_keys, nonce, aad, aad_len, pt, n, ct, tag);
#endif
    // The kernel's frames lay below this one and its values passed through the vector
    // registers, and the compiler clears neither on return.
    wipe_frame_call();
    avx512_wipe_registers();
}

void gcm_open_avx512(const uint8_t *round_keys, size_t rounds, const uint8_t nonce[AES_IV],
                     const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t n, uint8_t *pt,
                     uint8_t want[AES_BLOCK]) {
#ifdef CH_AES_256
    if (rounds == AES_256_ROUNDS) {
        gcm_avx512_open_256(round_keys, nonce, aad, aad_len, ct, n, pt, want);
    } else {
        gcm_avx512_open_128(round_keys, nonce, aad, aad_len, ct, n, pt, want);
    }
#else
    (void)rounds;
    gcm_avx512_open_128(round_keys, nonce, aad, aad_len, ct, n, pt, want);
#endif
    wipe_frame_call();
    avx512_wipe_registers();
}

#endif // CH_CPU_RUNTIME && (__x86_64__ || CH_GCM_AVX512_MODEL)
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
