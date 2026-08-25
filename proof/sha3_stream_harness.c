// Proves: the SHAKE streaming calls are memory-safe and UB-free from
// ANY context state a caller can hold — arbitrary lane contents,
// either rate, every write and read position — for split absorbs and
// split squeezes of up to 32 bytes each. The nondeterministic position
// reaches every block residue directly, so together with
// sha3_harness.c (whole messages from a fresh context) every sponge
// path runs under both a concrete and an arbitrary starting state.
// The chunks stay under both rates on purpose: the whole-block loops
// belong to sha3_harness.c, and keeping them out of this one keeps its
// formula small. The reachable states are a subset of what this
// assumes: absorb leaves pos below the rate, squeeze at most the rate.
#include "harness.h"

#include "sha3.c"

uint64_t nondet_u64(void);

// Typed stores: a byte-pointer fill of the uint64 lanes makes every
// store a whole-object update in the SSA (docs/proofs.md).
static void fill_context(shake *s) {
    for (size_t i = 0; i < 25; i++) {
        s->lane[i] = nondet_u64();
    }
    s->rate = nondet_size_t();
    __CPROVER_assume(s->rate == SHAKE128_RATE || s->rate == SHAKE256_RATE);
    s->pos = nondet_size_t();
}

int main(void) {
    uint8_t buf[32];
    fill_nondet(buf, sizeof buf);
    size_t a = nondet_size_t();
    size_t b = nondet_size_t();
    __CPROVER_assume(a <= sizeof buf);
    __CPROVER_assume(b <= sizeof buf - a);

    // Absorbing: any mid-message state, split delivery.
    shake s;
    fill_context(&s);
    s.squeezing = 0;
    __CPROVER_assume(s.pos < s.rate);
    shake_absorb(&s, buf, a);
    shake_absorb(&s, buf + a, b);
    __CPROVER_assert(s.pos < s.rate, "absorb leaves the position inside the block");

    // The first squeeze: pads at any write position.
    uint8_t out[32];
    fill_context(&s);
    s.squeezing = 0;
    __CPROVER_assume(s.pos < s.rate);
    shake_squeeze(&s, out, a);

    // Later squeezes: any read position, split output.
    fill_context(&s);
    s.squeezing = 1;
    __CPROVER_assume(s.pos <= s.rate);
    shake_squeeze(&s, out, a);
    shake_squeeze(&s, out + a, b);
    __CPROVER_assert(s.pos <= s.rate, "squeeze leaves the position at most one block in");
    return 0;
}
