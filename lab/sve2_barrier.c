// Lab only: chacha20_sve2.c with each XAR result pinned to a NEON register by an empty asm, so a
// spill of it is a 128-bit store. Timed beside the copy as it ships.
#include "chacha20_sve2.h"

#include <arm_neon.h>

#ifdef __clang__
#pragma clang attribute push(__attribute__((target("sve2"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("+sve2")
#endif

#include <arm_neon_sve_bridge.h>
#include <arm_sve.h>

static inline uint32x4_t pinned(uint32x4_t v) {
    __asm__("" : "+w"(v));
    return v;
}

#define LANES_XOR_ROTATE_LEFT(x, y, r)                                                             \
    pinned(svget_neonq_u32(svxar_n_u32(svset_neonq_u32(svundef_u32(), (x)),                        \
                                       svset_neonq_u32(svundef_u32(), (y)), 32 - (r))))

#define chacha20_vector_xor chacha20_sve2_barrier_xor
#include "chacha20_vector.c"

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif
