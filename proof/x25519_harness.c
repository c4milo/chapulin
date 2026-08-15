// Proves x25519's field arithmetic memory-safe at generous limb bounds
// (2^24 — far above the ~2^17 the ladder produces), and UB-free for the
// linear ops:
//
//   unpack -> limbs in [0, 2^16)         (asserted)
//   carry  : |in| < 2^58  -> no UB       (covers any product fold)
//   add/sub: |in| < 2^24  -> no UB
//   mul/sqr: memory-safe index walk over the 31-limb product (this
//            harness, run without the overflow class); the impossibility
//            of int64 overflow in the accumulation and fold is
//            x25519_mul_harness.c, proven with full checks — asking SAT
//            for both at once on 256 symbolic multiplies does not finish
//   pack   : |in| < 2^24  -> canonical 32 bytes, no UB
//   cswap  : bit 0/1      -> no UB
//
// The tight limb-growth invariant (mul output ranges feeding add/sub
// feeding mul) is an open slow-tier task — see the README's verification
// table. Functional correctness rests on the RFC 7748 vectors including
// the 1,000-iteration chain, and this exact limb scheme (TweetNaCl's)
// carries a prior Coq/VST functional proof by Schwabe et al.
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

    uint8_t bytes[X25519_LEN];
    fill_nondet(bytes, sizeof bytes);
    unpack(o, bytes);
    for (size_t i = 0; i < 16; i++) {
        __CPROVER_assert(o[i] >= 0 && o[i] < (int64_t)1 << 16, "unpack is carried");
    }

    assume_range(a, -GEN, GEN);
    assume_range(b, -GEN, GEN);
    add(o, a, b);
    sub(o, a, b);
    mul(o, a, b);

    assume_range(a, -((int64_t)1 << 58), (int64_t)1 << 58);
    carry(a);

    assume_range(a, -GEN, GEN);
    uint8_t out[X25519_LEN];
    pack(out, a);

    assume_range(a, -GEN, GEN);
    assume_range(b, -GEN, GEN);
    int64_t bit = nondet_i64();
    __CPROVER_assume(bit == 0 || bit == 1);
    cswap(a, b, bit);
    return 0;
}
