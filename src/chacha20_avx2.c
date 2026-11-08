#include "chacha20_avx2.h"

// The whole file compiles only in a host object on x86-64
// (chacha20_avx2.h).
#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

// Every function from here to the pop at the end of this file carries the
// target attribute that turns AVX2 on, and no function outside it does.
// clang applies it through one attribute push; gcc's target pragma sets
// it for each function defined after it, until the pop. The object is
// compiled with no instruction flag, so only these functions hold AVX2
// instructions, and chacha20.c calls them only where the caller's
// CH_CPU_AVX2 bit says the CPU has AVX2.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx2"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx2")
#endif

#include "chacha20_avx2_lanes.h"

void chacha20_avx2_xor(const uint8_t key[CHACHA20_KEY], const uint8_t nonce[CHACHA20_NONCE],
                       uint32_t counter, const uint8_t *in, uint8_t *out, size_t n) {
    uint32_t words[16];
    setup(words, key, nonce);
    xor_message(words, counter, in, out, n);
    // The registers hold a pass's state and keystream, which give the key,
    // and VZEROALL writes zero to all sixteen (docs/decisions.md 129).
    _mm256_zeroall();
}

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif

#endif // CH_CPU_RUNTIME && __x86_64__
