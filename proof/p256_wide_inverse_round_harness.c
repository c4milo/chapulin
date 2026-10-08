// Proves, for p256_wide_inverse.c: run_round, one round whole, for any state and any modulus,
// reads and writes inside its objects and shifts by no amount at or past a word's width: the
// approximations, the 31 steps and the four combinations, over proof/p256_wide_stubs.h's rows.
// The line runs without --unsigned-overflow-check, because the approximations and the steps wrap
// on purpose (p256_wide_inverse_steps_harness.c); p256_wide_inverse_harness.c proves the
// combinations with the check on.
//
// cbmc checks an access through s against the whole state, not against the member it names, so
// the helpers' accesses are held to their own four or five words by the harnesses that run them
// on separate objects, p256_wide_inverse_steps_harness.c and p256_wide_inverse_harness.c. A
// round names its members as whole values and indexes none itself.
//
// p256_wide_inverse is not run whole: its 17 rounds of 31 steps in one formula kept cbmc's
// symbolic execution going for 18 minutes with no formula at 360 MB. It sets the state's words
// from y and the modulus, runs run_round 17 times on that one state, copies v out and wipes the
// state once, so the proof of a round for any state covers each of the 17, and the rest indexes
// four words with the loop counter alone. p256_wide_inverse_public is the same loop, which also
// reads a's four words to stop at a zero a.
#include "p256_wide_stubs.h"

#include "p256_wide_inverse.c"

static void words_nondet(uint64_t x[WORDS]) {
    for (size_t i = 0; i < WORDS; i++) {
        x[i] = nondet_u64();
    }
}

int main(void) {
    p256_wide_modulus m;
    words_nondet(m.word);
    m.negated_inverse = nondet_u64();
    inverse_state s;
    words_nondet(s.a.word);
    words_nondet(s.b.word);
    words_nondet(s.u.word);
    words_nondet(s.v.word);
    run_round(&s, &m);
    return 0;
}
