// Proves: mul's memory-safe index walk over the 31-limb product, at
// generous limb bounds (2^24 — far above the ~2^17 the ladder
// produces), with distinct operands. The aliasing shapes the callers
// use are one formula each — x25519_mul_alias_a (mul(c, c, a)),
// x25519_mul_alias_b (mul(a, c, a)), x25519_mul_inputs_alias
// (sqr(d, e)), and x25519_sqr (invert's sqr(c, c)) — because one
// 64-bit limb multiply fills a formula near the solver cap: two in one
// was killed at 7 GB, four at 14 GB.
//
// This harness runs without the signed-overflow class: mul's 256
// symbolic multiplies never converge under SAT with it. The class is
// carried elsewhere — x25519_mul_harness.c proves the int64
// accumulation and fold lemma, and x25519_ops_harness.c proves carry,
// add, sub, pack, cswap, and unpack whole with full checks — so the
// x25519 harnesses together cover every field op, each with the
// strongest check set that converges.
//
// The tight limb-growth invariant (mul output ranges feeding add/sub
// feeding mul) is an open slow-tier task — see the README's
// verification table. Functional correctness rests on the RFC 7748
// vectors including the 1,000-iteration chain, and this exact limb
// scheme (TweetNaCl's) carries a prior Coq/VST functional proof by
// Schwabe et al.
#include "harness.h"

#include "x25519.c"

#define GEN ((int64_t)1 << 24)

static void assume_range(fe f, int64_t lo, int64_t hi) {
    for (size_t i = 0; i < 16; i++) {
        f[i] = nondet_i64();
        __CPROVER_assume(f[i] >= lo && f[i] < hi);
    }
}

int main(void) {
    fe a;
    fe b;
    fe o;

    assume_range(a, -GEN, GEN);
    assume_range(b, -GEN, GEN);
    mul(o, a, b);
    return 0;
}
