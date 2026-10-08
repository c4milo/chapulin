// The reference step p256_wide_inverse_steps_harness.c and p256_wide_inverse_range_harness.c hold
// p256_wide_inverse.c's step to: the binary GCD's step with branches, on the approximations and
// on the four factors, each factor a signed 64-bit integer in its own variable. Its moves are
// spec/lean/Spec/P256WideInverse.lean's move, apply and applyFactors.
#ifndef CH_PROOF_P256_WIDE_INVERSE_REFERENCE_H
#define CH_PROOF_P256_WIDE_INVERSE_REFERENCE_H

#include <stdint.h>

typedef struct {
    uint64_t xa;
    uint64_t xb;
    int64_t f0;
    int64_t g0;
    int64_t f1;
    int64_t g1;
} reference_state;

// When xa is odd and below xb, the two swap, factors with them; when xa is odd, xb and its
// factors are subtracted from xa and its; then xa is halved and the second factors doubled.
static void reference_step(reference_state *s) {
    if ((s->xa & 1) != 0) {
        if (s->xa < s->xb) {
            uint64_t t = s->xa;
            s->xa = s->xb;
            s->xb = t;
            int64_t f = s->f0;
            s->f0 = s->f1;
            s->f1 = f;
            int64_t g = s->g0;
            s->g0 = s->g1;
            s->g1 = g;
        }
        s->xa -= s->xb;
        s->f0 -= s->f1;
        s->g0 -= s->g1;
    }
    s->xa >>= 1;
    s->f1 *= 2;
    s->g1 *= 2;
}

// f + 2^32 g modulo 2^64, the word step_factors keeps a pair of factors in.
static uint64_t reference_pack(int64_t f, int64_t g) {
    return (uint64_t)f + ((uint64_t)g << 32);
}

#endif
