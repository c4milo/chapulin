// Proves: the arithmetic modulo L of x25519_wide_ed25519_sign.h, which
// Ed25519 signing runs on secret scalars, is UB-free and gives the value
// its comments state, over every input in its domain:
// - scalar_settle takes an o below 2 L to o less L when o is at or above
//   L, and leaves it otherwise, so the result is below L;
// - scalar_add takes o and a below L to their sum modulo L;
// - scalar_double takes o below L and a bit to 2 o + bit modulo L;
// - one step of scalar_muladd's loop, a double and then an add of k or of
//   zero by mask, keeps the sum below L. The loop starts from 0, so by
//   induction its 256 steps end below L.
// The reference sums below are plain word arithmetic with branches, apart
// from the code under proof, which selects by mask. What the two loops
// compute is not proved here: spec/lean/Spec/Ed25519Sign.lean proves on a
// model of the C that scalar_reduce writes h mod L and scalar_muladd
// r + k a mod L, and bin/diff_ed25519 holds the C to the model.
// bin/jws_sign_test holds the whole signature to RFC 8032 section 7.1's
// five, byte for byte.
#define CH_JWS 1
#include "x25519_wide_stubs.h"

// The 5-word sum a + b of two 4-word values, the fifth word the carry.
static void ref_add(uint64_t o[5], const uint64_t a[4], const uint64_t b[4]) {
    uint64_t carry = 0;
    for (size_t i = 0; i < 4; i++) {
        uint64_t s = a[i] + b[i];
        uint64_t c1 = s < a[i];
        uint64_t t = s + carry;
        uint64_t c2 = t < s;
        o[i] = t;
        carry = c1 + c2;
    }
    o[4] = carry;
}

// Whether the 5-word x equals the 4-word y plus L times times (0 or 1).
static int equals_plus_l(const uint64_t x[5], const uint64_t y[4], int times) {
    static const uint64_t zero[4] = {0, 0, 0, 0};
    uint64_t sum[5];
    ref_add(sum, y, times ? ED25519_L : zero);
    for (size_t i = 0; i < 5; i++) {
        if (sum[i] != x[i]) {
            return 0;
        }
    }
    return 1;
}

static void below_l(uint64_t o[4]) {
    for (size_t i = 0; i < 4; i++) {
        o[i] = nondet_u64();
    }
    __CPROVER_assume(!at_or_above_l(o));
}

int main(void) {
    uint8_t part = nondet_u8();
    uint64_t o[4];
    uint64_t a[4];
    below_l(o);
    below_l(a);
    uint64_t in[5] = {o[0], o[1], o[2], o[3], 0};
    if (part == 0) {
        // o + a, which is below 2 L, then settled.
        uint64_t sum[5];
        ref_add(sum, o, a);
        scalar_add(o, a);
        __CPROVER_assert(!at_or_above_l(o), "scalar_add leaves the sum below L");
        __CPROVER_assert(equals_plus_l(sum, o, 0) || equals_plus_l(sum, o, 1),
                         "scalar_add gives the sum less L or the sum");
    } else if (part == 1) {
        uint64_t bit = nondet_u64() & 1;
        uint64_t doubled[4] = {(o[0] << 1) | bit, (o[1] << 1) | (o[0] >> 63),
                               (o[2] << 1) | (o[1] >> 63), (o[3] << 1) | (o[2] >> 63)};
        uint64_t twice[5] = {doubled[0], doubled[1], doubled[2], doubled[3], o[3] >> 63};
        scalar_double(o, bit);
        __CPROVER_assert(!at_or_above_l(o), "scalar_double leaves the value below L");
        __CPROVER_assert(equals_plus_l(twice, o, 0) || equals_plus_l(twice, o, 1),
                         "scalar_double gives 2 o + bit, less L or not");
    } else if (part == 2) {
        // One step of scalar_muladd's loop, with k below L and either mask.
        uint64_t mask = nondet_u64() & 1 ? UINT64_MAX : 0;
        uint64_t term[4];
        scalar_double(o, 0);
        for (size_t i = 0; i < 4; i++) {
            term[i] = a[i] & mask;
        }
        scalar_add(o, term);
        __CPROVER_assert(!at_or_above_l(o), "a step of scalar_muladd keeps the sum below L");
    } else {
        // scalar_settle alone, from any value below 2 L.
        uint64_t extra = nondet_u64() & 1;
        uint64_t x[5];
        ref_add(x, o, extra ? ED25519_L : (const uint64_t[4]){0, 0, 0, 0});
        __CPROVER_assume(x[4] == 0);
        uint64_t settled[4] = {x[0], x[1], x[2], x[3]};
        scalar_settle(settled);
        __CPROVER_assert(!at_or_above_l(settled), "scalar_settle leaves the value below L");
        __CPROVER_assert(equals_plus_l(x, settled, (int)extra),
                         "scalar_settle subtracts L exactly when the value is at or above L");
        (void)in;
    }
    return 0;
}
