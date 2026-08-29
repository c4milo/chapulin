// Constant-time byte operations. Everything in the stack that touches
// secret bytes compares through ct_memeq and wipes through ct_wipe; no
// secret ever decides a branch or a memory index anywhere else either.
#ifndef CH_CT_H
#define CH_CT_H

#include <stddef.h>
#include <stdint.h>

// 1 if a[0..n) == b[0..n), 0 otherwise. Time depends only on n.
uint32_t ct_memeq(const uint8_t *a, const uint8_t *b, size_t n);

// Zeroizes p[0..n) through a volatile pointer so the store survives
// dead-store elimination.
void ct_wipe(void *p, size_t n);

// Whether the target's widening multiply is constant-time is a claim about
// silicon, and no architecture macro carries it.
//
// This header used to grant __x86_64__ and __aarch64__ that claim, and refuse
// riscv for lacking one. The refusal was right and the grants were not, on the
// same evidence: RISC-V publishes Zkt to attest data-independent latency, Arm
// publishes FEAT_DIT and Intel publishes DOITM, and all three exist because
// the base architectures do not promise it. A part that does not declare the
// feature promises nothing, whichever vendor made it. The mechanism cannot be
// repaired either -- clang defines no __ARM_FEATURE_DIT even at
// -march=armv8.4-a+dit, so the preprocessor cannot tell a part that has it
// from one that does not.
//
// So there is no list. Every target gets the decomposition unless its build
// says otherwise, which is the safe default: being wrong about a part costs
// speed, where the old default cost the guarantee silently.
//
// Two macros steer it, and CH_CT_WIDEMUL wins when both are set:
//
//   CH_NATIVE_WIDEMUL  the build asserts this part multiplies in constant
//                      time. The Makefile passes it for host test binaries,
//                      where nothing secret is at risk and solver time is;
//                      firmware passes it only with a vendor statement.
//   CH_CT_WIDEMUL      force the decomposition, whatever else is set.
//                      bin/timing and proof/ctwidemul_harness.c use it to
//                      measure and prove the path that ships.
//
// What the decomposition rests on, stated plainly: it removes the 32-to-64
// multiply, and what is left is the 32-to-32 one. ARM documents that as
// single-cycle on the M3, so the guarantee is complete there. mips32r2 is
// weaker -- GCC's 4K scheduler model says the 3-operand mul stalls by operand
// size, so the decomposition narrows every operand to 16 bits and makes the
// sequence uniform, but the residual timing of mul itself is undocumented. A
// part that must not depend on that needs a build with no multiply
// instruction at all, which softmul.c supplies only where the compiler
// already emits calls (a core with no multiplier). Closing that gap for a
// core that has a variable-time multiplier is not done.
//
// See https://github.com/c4milo/chapulin/issues/53.
#if defined(CH_NATIVE_WIDEMUL) && !defined(CH_CT_WIDEMUL)
#define CH_WIDEMUL_NATIVE 1
#endif

// a * b, widened, using only 32-to-32 multiplies.
//
// A 32-to-64 multiply is variable-time on some cores -- the Cortex-M3's umull
// returns sooner when both operands are below 65536, and has undocumented
// early exits on zero and powers of two, which has been used to extract
// Curve25519 keys. Its 32-to-32 mul is constant-time, so four 16x16 products
// and a recombination out of shifts and adds are not. The operands' halves are
// full width by construction, so nothing here depends on the values (INV-16,
// https://github.com/c4milo/chapulin/issues/53).
static inline uint64_t ct_widemul(uint32_t a, uint32_t b) {
#ifdef CH_WIDEMUL_NATIVE
    return (uint64_t)a * b;
#else
    uint32_t al = a & 0xFFFFU;
    uint32_t ah = a >> 16;
    uint32_t bl = b & 0xFFFFU;
    uint32_t bh = b >> 16;
    uint32_t ll = al * bl;
    uint32_t lh = al * bh;
    uint32_t hl = ah * bl;
    uint32_t hh = ah * bh;
    uint64_t mid = (uint64_t)lh + hl;
    return ((uint64_t)hh << 32) + (mid << 16) + ll;
#endif
}

// a * k for a 64-bit a and a small constant k, low 64 bits.
//
// Writing a constant multiply as shifts does not work: the optimiser
// recognises the pattern and emits the wide multiply again. Routing the
// low half through ct_widemul survives, because four 16x16 products are
// not a shape it folds back.
static inline uint64_t ct_mulsmall(uint64_t a, uint32_t k) {
#ifdef CH_WIDEMUL_NATIVE
    return a * k;
#else
    uint64_t lo = ct_widemul((uint32_t)a, k);
    uint32_t hi = (uint32_t)(a >> 32) * k; // only the low 32 bits survive the shift
    return lo + ((uint64_t)hi << 32);
#endif
}

// The signed form. Two's complement makes a signed product the unsigned
// one over the same bit patterns, less b<<32 when a is negative and a<<32
// when b is negative; the corrections are masked rather than branched, so
// the sign of a secret limb stays off the control path.
static inline int64_t ct_widemul_s(int32_t a, int32_t b) {
#ifdef CH_WIDEMUL_NATIVE
    return (int64_t)a * b;
#else
    uint32_t ua = (uint32_t)a;
    uint32_t ub = (uint32_t)b;
    uint64_t p = ct_widemul(ua, ub);
    uint64_t ma = (uint64_t)0 - (uint64_t)(ua >> 31);
    uint64_t mb = (uint64_t)0 - (uint64_t)(ub >> 31);
    p -= ((uint64_t)ub << 32) & ma;
    p -= ((uint64_t)ua << 32) & mb;
    return (int64_t)p;
#endif
}

#endif
