// The kernel gcm_avx512.c's two entries call: SP 800-38D's whole GCM-AE and whole GCM-AD for a
// 96-bit IV, four blocks to a 512-bit register, on VAES and VPCLMULQDQ with AVX-512F and
// AVX-512BW (docs/decisions.md 130). One function for each key size and each direction, so that
// each holds its round count as a constant and its round loops unroll.
//
// A pair of its own, apart from gcm_avx512.c, for two reasons. Its frames lie in the stack below
// the entry's frame, where the entry wipes them after each call. And lint-stack holds every
// function here under a ceiling of its own, STACK_BUDGET_GCM_AVX512, which the Makefile computes
// from GCM_AVX512_BELOW_LEN below, while gcm_avx512.c holds the wipe's array of that length.
//
// Every name begins gcm_, so inv-26-aes-public-keys-only matches a call from any library source
// outside gcm_avx512.c, and `make lint-quic-surface` reads this header for that prefix. The
// round keys are a public key's or a traffic key's, so INV-26 bounds these functions the way it
// bounds gcm_hw.c's.
#ifndef CH_GCM_AVX512_KERNEL_H
#define CH_GCM_AVX512_KERNEL_H
#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#ifdef CH_CPU_RUNTIME

#include <stddef.h>
#include <stdint.h>

#include "aes.h"

// The kernel exists on x86-64 alone. On any other target gcm_avx512_kernel.c compiles to nothing
// but these includes. A proof unit that defines CH_GCM_AVX512_MODEL reads the length and the
// declarations below on any target, for gcm_avx512.c's entries, which it compiles over contract
// stubs of the four functions (proof/gcm_avx512_wipe_harness.c).
#if defined(__x86_64__) || defined(CH_GCM_AVX512_MODEL)

// The bytes of stack gcm_avx512.c's entries wipe below their own frames after each kernel call.
// A kernel leaves the powers of the hash subkey in its frame, and beside them whatever its
// compiler wrote to stack slots of its own: round keys, keystream, the hash subkey, the tag's
// mask and GHASH sums, which no ct_wipe can name.
//
// A kernel calls no function. Every other function in gcm_avx512_kernel.c and
// gcm_avx512_ghash.h carries always_inline, and lint-stack and test/quic-builds.sh fail when the
// kernel's object defines one, so a kernel's frame is all the stack it writes. lint-stack holds
// each kernel's frame under STACK_BUDGET_GCM_AVX512, which the Makefile sets to this length less
// 512 bytes: the room a kernel takes beside its frame, for the six registers it saves, its
// return address, the alignment of its frame to 64 bytes, the 128-byte red zone below it and
// the two arguments its caller passes on the stack. bin/gcm_avx512_equiv_test measures how far
// below its caller each kernel writes and requires that inside this length.
//
// For x86-64, -fstack-usage, which counts a frame with the registers saved, the return address
// and the alignment, reported at most 1,152 bytes for a kernel under gcc 13.3 at -O2, 1,536 at
// -O1 and 2,112 at -Og, and at most 952 under clang 23 at any level from -Og to -O3 and -Os, for
// the baseline target and for x86-64-v4 (docs/decisions.md 130). At -O0 a kernel keeps every
// intrinsic's value in a slot of its own and its frame passes this length, so the wipe then
// leaves part of it, and bin/gcm_avx512_equiv_test makes no search of the stack in an
// unoptimized binary (INV-17).
#define GCM_AVX512_BELOW_LEN 2560

// GCM-AE under AES-128 round keys: ct gets the n ciphertext bytes of the n plaintext bytes at pt,
// and tag the 16-byte tag over the aad_len bytes at aad and the ciphertext.
//
// Requires: round_keys points at AES_ROUND_KEYS * AES_BLOCK readable bytes that
// aes_expand_round_keys wrote; nonce points at AES_IV readable bytes; aad at aad_len readable
// bytes, and may be NULL when aad_len is 0; pt at n readable bytes and ct at n writable bytes,
// either NULL when n is 0, with pt == ct allowed and no other overlap; tag at AES_BLOCK writable
// bytes outside the others. A CPU with AVX-512F, AVX-512BW, VAES and VPCLMULQDQ, which
// gcm_use_avx512 decides from the session's bits: on a CPU without them the first instruction
// faults. Reads and writes no byte outside those ranges, and cannot fail.
void gcm_avx512_seal_128(const uint8_t *round_keys, const uint8_t nonce[AES_IV], const uint8_t *aad,
                         size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                         uint8_t tag[AES_BLOCK]);

// GCM-AD under AES-128 round keys, without the comparison: pt gets the n plaintext bytes of the
// n ciphertext bytes at ct, and want the tag those bytes and the associated data should carry.
// Every block of ct is hashed before any plaintext byte is written over it.
//
// Requires: what gcm_avx512_seal_128 requires, with ct readable and pt writable for n bytes, and
// pt == ct, pt below ct or no overlap allowed; want points at AES_BLOCK writable bytes outside
// the others.
void gcm_avx512_open_128(const uint8_t *round_keys, const uint8_t nonce[AES_IV], const uint8_t *aad,
                         size_t aad_len, const uint8_t *ct, size_t n, uint8_t *pt,
                         uint8_t want[AES_BLOCK]);

#ifdef CH_AES_256
// The same two under AES-256 round keys: round_keys points at AES_256_ROUND_KEYS * AES_BLOCK
// readable bytes that aes_expand_round_keys_256 wrote.
void gcm_avx512_seal_256(const uint8_t *round_keys, const uint8_t nonce[AES_IV], const uint8_t *aad,
                         size_t aad_len, const uint8_t *pt, size_t n, uint8_t *ct,
                         uint8_t tag[AES_BLOCK]);
void gcm_avx512_open_256(const uint8_t *round_keys, const uint8_t nonce[AES_IV], const uint8_t *aad,
                         size_t aad_len, const uint8_t *ct, size_t n, uint8_t *pt,
                         uint8_t want[AES_BLOCK]);
#endif

#endif // __x86_64__ || CH_GCM_AVX512_MODEL
#endif // CH_CPU_RUNTIME
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
#endif
