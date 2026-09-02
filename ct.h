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
//                      measure and prove the path that ships, and
//                      `make ct-widemul-check` runs the unit, ML-KEM and
//                      Wycheproof vectors over it.
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
//
// The recombination is Hacker's Delight's mulhu ladder in 32-bit arithmetic,
// and the two words meet only in the last line. None of its sums can
// overflow: each product is at most (2^16-1)^2, each shifted-down piece at
// most 2^16-1, and t, w1 and hi are one product plus one or two such pieces.
// Keeping every sum in 32 bits is what defeats gcc: `(uint64_t)lh + hl`, the
// form this used to take, is a 64-bit sum of a product gcc can prove fits 32
// bits, and gcc's widening_mul pass turns that into one umlal per call on the
// M3 (45 in poly1305 at -O2, where it widened more of the sum)
// (https://github.com/c4milo/chapulin/issues/106). Here nothing is widened
// before an add, so there is nothing for the pass to find.
//
// A compiler can add a pattern, so the form proves nothing by itself:
// lint-wide-multiply and lint-wide-multiply-gcc read what each compiler emits
// and hold every file at zero, and ct_widemul_opaque below is the one caller
// shape that needed a different form.
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
    uint32_t t = hl + (ll >> 16);
    uint32_t w1 = (t & 0xFFFFU) + lh;
    uint32_t hi = hh + (t >> 16) + (w1 >> 16);
    uint32_t lo = (w1 << 16) | (ll & 0xFFFFU);
    return ((uint64_t)hi << 32) | lo;
#endif
}

// a * b, widened, for a caller whose operands the compiler can prove narrow.
//
// ct_widemul is four 16x16 products, and the optimiser is entitled to drop the
// ones it can prove are zero. Where it proves a whole half zero it collapses
// the remainder and may re-synthesize the widening instruction the
// decomposition existed to avoid: clang 22 at -Os does exactly that for
// mlk_compress on rv32imac, emitting slli then mulhu on the path that decodes
// the shared secret.
//
// Reading the operands through volatile stops the inference, at the cost of a
// store and a load each. That is why this is a separate entry rather than
// ct_widemul's behaviour: the barrier costs 45% of poly1305's block on a
// Cortex-M3, and poly1305 does not need it -- its operands are wide by
// construction, so nothing is provably zero. Use this only where a caller's
// operand has a compile-time bound under 2^16, and say so at the call site.
//
// The recombination is not ct_widemul's. mlk_compress reads only the high
// word of the product, and LLVM's AggressiveInstCombine (foldMulHigh) knows
// the ladder above, and three other shift-and-mask shapes, as the high word
// of a 32x32 product: where the low word is dead it replaces the four
// products with one widening multiply -- umull on the M3, mulhu on rv32imac,
// multu on mips32r2 -- volatile operands or not
// (https://github.com/c4milo/chapulin/issues/106). It does not know a carry
// taken as a compare, `sum < addend`, so this form takes its two carries that
// way. It costs more than the ladder, which is why ct_widemul does not use it.
static inline uint64_t ct_widemul_opaque(uint32_t a, uint32_t b) {
#ifdef CH_WIDEMUL_NATIVE
    return (uint64_t)a * b;
#else
    volatile uint32_t va = a;
    volatile uint32_t vb = b;
    uint32_t oa = va;
    uint32_t ob = vb;
    uint32_t al = oa & 0xFFFFU;
    uint32_t ah = oa >> 16;
    uint32_t bl = ob & 0xFFFFU;
    uint32_t bh = ob >> 16;
    uint32_t ll = al * bl;
    uint32_t lh = al * bh;
    uint32_t hl = ah * bl;
    uint32_t hh = ah * bh;
    uint32_t mid = lh + hl;
    uint32_t mid_carry = (uint32_t)(mid < lh);
    uint32_t lo = ll + (mid << 16);
    uint32_t lo_carry = (uint32_t)(lo < ll);
    uint32_t hi = hh + (mid >> 16) + (mid_carry << 16) + lo_carry;
    return ((uint64_t)hi << 32) | lo;
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
// when b is negative, so only the high word moves. Each correction is
// masked, never branched: the mask is the operand's sign bit spread across
// the word by an arithmetic shift, so the sign of a secret limb stays off
// the control path. It used to be `0 - (ua >> 31)`, and gcc's match.pd
// rewrites `X & -Y` as `X * Y` when it knows Y is 0 or 1 -- a widening
// multiply by a secret bit, two umull in x25519 on the M3 and one mulhu on
// rv32imac (https://github.com/c4milo/chapulin/issues/106). A shifted sign
// bit is not a negated 0-or-1 value, so the rule does not apply.
static inline int64_t ct_widemul_s(int32_t a, int32_t b) {
#ifdef CH_WIDEMUL_NATIVE
    return (int64_t)a * b;
#else
    uint32_t ua = (uint32_t)a;
    uint32_t ub = (uint32_t)b;
    uint64_t p = ct_widemul(ua, ub);
    uint32_t ma = (uint32_t)(a >> 31);
    uint32_t mb = (uint32_t)(b >> 31);
    uint32_t hi = (uint32_t)(p >> 32) - (ub & ma) - (ua & mb);
    return (int64_t)(((uint64_t)hi << 32) | (uint32_t)p);
#endif
}

#endif
