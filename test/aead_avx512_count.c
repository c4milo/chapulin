// chacha20_avx512.c's entry as a count and a call to chacha20_vector_xor,
// and poly1305_ifma.c's native entry, under the name the counting units
// give it, as a call to the 128-bit path's native entry under the name
// they give that, for the binaries that link this file in place of the two
// (test/aead_avx512_count.h). chacha20_vector_xor writes the bytes
// chacha20_avx512_xor writes, and poly1305_vector_blocks_native_counted
// leaves the accumulator poly1305_ifma_blocks leaves, because a group of
// sixteen blocks is four of its groups. The entries compile under the
// condition their headers declare them under, so on arm64 this file holds
// the count alone.
#include "aead_avx512_count.h"

#include "aead_avx2.h"
#include "chacha20_avx2.h"
#include "chacha20_avx512.h"
#include "chacha20_vector.h"

unsigned long chacha20_avx512_calls;
unsigned long aead_avx2_seal_calls;
unsigned long aead_avx2_open_calls;

#ifdef CH_AEAD_AVX2
// The one pass's entries as the two-pass AEAD's two calls, in the order
// each runs them (test/aead_avx512_count.h).
void aead_avx2_seal(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                    poly1305 *p, const uint8_t *pt, size_t n, uint8_t *ct) {
    aead_avx2_seal_calls++;
    chacha20_avx2_xor(key, nonce, 1, pt, ct, n);
    poly1305_update_avx2_native(p, ct, n);
}

void aead_avx2_open(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                    poly1305 *p, const uint8_t *ct, size_t n, uint8_t *pt) {
    aead_avx2_open_calls++;
    poly1305_update_avx2_native(p, ct, n);
    chacha20_avx2_xor(key, nonce, 1, ct, pt, n);
}
#endif

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

void chacha20_avx512_xor(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                         uint32_t counter, const uint8_t *in, uint8_t *out, size_t n) {
    chacha20_avx512_calls++;
    chacha20_vector_xor(key, nonce, counter, in, out, n);
}

// The name test/widemul_count_native_vector.c gives the 128-bit path's
// native entry.
void poly1305_vector_blocks_native_counted(poly1305 *p, const uint8_t *m, size_t n);

void poly1305_ifma_blocks_native_counted(poly1305 *p, const uint8_t *m, size_t n) {
    poly1305_vector_blocks_native_counted(p, m, n);
}

#endif // CH_CPU_RUNTIME && __x86_64__
