#include "poly1305_ifma.h"

// The whole file compiles only under CH_POLY1305_IFMA (poly1305_ifma.h):
// in an x86-64 host object's native copy.
#ifdef CH_POLY1305_IFMA

// avx512_wipe.h comes before the attribute push below, so its declaration
// carries no target attribute: clang reads a declaration under the push
// and avx512_wipe.c's definition under target("avx512f") alone as two
// versions of one function, and refuses a unit that holds both.
#include "avx512_wipe.h"
#include "ch_assert.h"
#include "ct.h"
// carry_scalar alone: the kernel computes its powers of r in the lanes.
#define POLY1305_SCALAR_CARRY_ONLY
#include "poly1305_scalar.h"

#ifdef CH_POLY1305_IFMA_MODEL
// Each lane operation in portable C (test/poly1305_ifma_model_lanes.h),
// which only a build with -Itest finds.
#include "poly1305_ifma_model_lanes.h"
#else
// Every function from here to the pop at the end of this file carries the
// target attribute that turns AVX-512F and AVX-512 IFMA on, and no function
// outside it does, as in poly1305_avx2.c: poly1305_scalar.h's carry above
// compiles without it. The object is compiled with no instruction flag,
// and build.zig adds only the evex512 feature, which turns on no
// instruction. So only these functions hold AVX-512 instructions, and
// poly1305.c calls them only for an update that
// widemul_poly1305_update_cpu started for a session whose ch_cfg.cpu holds
// CH_CPU_AVX512_IFMA beside the multiply bit.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx512f,avx512ifma"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx512f,avx512ifma")
#endif

#include "poly1305_ifma_lanes.h"
#endif

#include "poly1305_ifma_group.h"

void poly1305_ifma_blocks(poly1305 *p, const uint8_t *m, size_t n) {
    CH_ASSERT(n > 0 && n % POLY1305_IFMA_GROUP == 0);
    powers of_r;
    compute_powers(&of_r, p->r);

    // Lane 0 starts from the accumulator and lanes 1 to 7 from 0.
    uint64_t start[3];
    digits_of_words(start, p->h);
    lanes h[3];
    h[0] = lanes_first_only(start[0]);
    h[1] = lanes_first_only(start[1]);
    h[2] = lanes_first_only(start[2]);
    lanes lo[3];
    lanes hi[3];
    for (; n > POLY1305_IFMA_GROUP; n -= POLY1305_IFMA_GROUP) {
        group_sums(lo, hi, h, m, &of_r.by_16, &of_r.by_8);
        carry(h, lo, hi);
        m += POLY1305_IFMA_GROUP;
    }
    group_sums(lo, hi, h, m, &of_r.last_first, &of_r.last_second);
    carry(h, lo, hi);

    // The eight lanes' digits add up to the accumulator. Each digit is below
    // 2^45, so each total is below 2^48.
    uint64_t total[3];
    total[0] = lanes_total(h[0]);
    total[1] = lanes_total(h[1]);
    total[2] = lanes_total(h[2]);
    // The powers, the sums and the accumulator's lanes passed through the
    // vector registers, and the compiler clears none of them on return:
    // lanes_wipe_registers is avx512_wipe_registers. No vector is live past
    // this call, so the compiler keeps none on the stack across it.
    lanes_wipe_registers();
    words_of_totals(p->h, total);
    ct_wipe(&of_r, sizeof of_r);
}

#ifndef CH_POLY1305_IFMA_MODEL
#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif
#endif

#endif // CH_POLY1305_IFMA
