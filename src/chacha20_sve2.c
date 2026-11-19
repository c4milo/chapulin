// chacha20_vector.c compiled once more for an arm64 host object, with SVE2's XAR in its quarter
// rounds (chacha20_sve2.h).
#include "chacha20_sve2.h"

#ifdef CH_CHACHA20_SVE2

#include <arm_neon.h>

// Every function from here to the pop at the end of this file carries the target attribute that
// turns SVE2 on, the copied text's too, and no function outside it does. clang applies it
// through one attribute push; gcc's target pragma sets it for each function defined after it,
// until the pop. The object is compiled with no instruction flag, so only these functions hold
// SVE2 instructions, and chacha20.c calls them only where the caller's CH_CPU_SVE2 bit says the
// CPU has SVE2.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("sve2"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("+sve2")
#endif

#include <arm_neon_sve_bridge.h>
#include <arm_sve.h>

// The step chacha20_vector.c names LANES_XOR_ROTATE_LEFT, as one SVE2 XAR. XAR XORs two vectors
// and rotates each 32-bit lane right, so a rotation left by r is a rotation right by 32 - r. A
// NEON register is the low 128 bits of the SVE register with the same number, so the bridge calls
// move no data. Where the vector length is longer, XAR also computes the lanes above bit 127, and
// svget_neonq_u32 drops them, so the copy computes the same keystream at every vector length.
// svundef_u32 leaves those lanes undefined, and nothing reads them.
#define LANES_XOR_ROTATE_LEFT(x, y, r)                                                             \
    LANES_HOLD(svget_neonq_u32(svxar_n_u32(svset_neonq_u32(svundef_u32(), (x)),                    \
                                           svset_neonq_u32(svundef_u32(), (y)), 32 - (r))))

// Under gcc each step's result passes through an empty statement that holds it in a NEON
// register. It emits no instruction. Without it gcc 15 kept some results in whole SVE registers
// through the round loop, and wrote them to stack slots it addressed with ADDVL and ADD. On a
// Neoverse N2 the copy then took 0.67 of the NEON path's time over 16 KiB, and 0.54 with it; gcc
// 14 took 0.60 and 0.57. Under clang 23 it raised the time from 0.61 to 0.64, so clang compiles
// none (docs/decisions.md 242).
#ifdef __clang__
#define LANES_HOLD(v) (v)
#else
static inline uint32x4_t lanes_hold(uint32x4_t v) {
    __asm__("" : "+w"(v));
    return v;
}
#define LANES_HOLD(v) lanes_hold(v)
#endif

// chacha20_vector.h is read below with the rename in place, so it declares chacha20_sve2_xor.
#define chacha20_vector_xor chacha20_sve2_xor

#include "chacha20_vector.c"

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif

#endif // CH_CHACHA20_SVE2
