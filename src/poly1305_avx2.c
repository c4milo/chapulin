#include "poly1305_avx2.h"

// The whole file compiles only under CH_POLY1305_AVX2 (poly1305_avx2.h):
// in an x86-64 host object's native copy.
#ifdef CH_POLY1305_AVX2

#include "ch_assert.h"
#include "poly1305_scalar.h"

// Every function from here to the pop at the end of this file carries the
// target attribute that turns AVX2 on, and no function outside it does,
// as in chacha20_avx2.c: poly1305_scalar.h's steps above compile without
// it. The object is compiled with no instruction flag, so only these
// functions hold AVX2 instructions, and poly1305.c calls them only for an
// update that widemul_poly1305_update_cpu started for a session whose
// ch_cfg.cpu holds CH_CPU_AVX2.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx2"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx2")
#endif

#include "poly1305_avx2_lanes.h"

void poly1305_avx2_blocks(poly1305 *p, const uint8_t *m, size_t n) {
    CH_ASSERT(n > 0 && n % POLY1305_AVX2_GROUP == 0);
    powers of_r;
    words h[5];
    run_start(&of_r, h, p);
    run_finish(&of_r, h, p, m, n);
}

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif

#endif // CH_POLY1305_AVX2
