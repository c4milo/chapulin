// Proves: sha3.c's round, written out lane by lane, computes what FIPS
// 202's five step algorithms compute, for every 1,600-bit state and every
// round constant. proof/sha3_reference.h holds those algorithms as the
// standard writes them: loops over a lane's column and row, with the rho
// offsets computed by the standard's rule. Both are XORs, AND-NOTs and
// fixed rotations of the same 25 lanes, so the solver sees two circuits
// of one function.
//
// And the 24 rounds. sha3.c's table holds the 24 constants the standard's
// shift register produces, each compared with the reference's. Then
// keccak_f1600 and 24 rounds of the reference leave the same state from
// the state of zeros. Both inputs are concrete, so both checks are
// evaluations. A permutation that ran a round too few, or read a constant
// out of its order, would leave another state, because every round is a
// bijection.
//
// And the inverted lanes form (docs/decisions.md 195 and 216). Its round
// reads one state and writes a second one. Run on a state with
// invert_lanes' six lanes inverted, it writes the standard's round's
// state with the same six lanes inverted, for every state and every round
// constant. Its 24 rounds between the two calls of invert_lanes leave
// Keccak-f[1600]'s state from zeros, and its scratch state holds zeros
// after them.
//
// And the ANDN form that sha3_hw.c's x86-64 copy runs (docs/decisions.md
// 217). Its round reads one state and writes a second one with FIPS 202's
// chi, and writes the standard's round's state for every state and every
// round constant. Its 24 rounds leave Keccak-f[1600]'s state from zeros,
// and its scratch state holds zeros after them. The copy compiles this C
// under target("bmi,bmi2"), which changes the instructions and not the
// function the C computes.
//
// Together: each round is the standard's for every input, and each form
// of the permutation applies it 24 times with the standard's constants
// in the standard's order, so the three forms are the standard's.
#include "harness.h"

#include "sha3.c"

#include "proof/sha3_reference.h"

uint64_t nondet_u64(void);

int main(void) {
    uint64_t standard[25];
    uint64_t written[25];
    for (size_t i = 0; i < 25; i++) {
        standard[i] = nondet_u64();
        written[i] = standard[i];
    }
    uint64_t round_constant = nondet_u64();
    uint64_t before[25];
    uint64_t inverted[25];
    uint64_t andn[25];
    for (size_t i = 0; i < 25; i++) {
        before[i] = standard[i];
    }
    keccak_round_andn(andn, before, round_constant);
    invert_lanes(before);
    reference_round(standard, round_constant);
    keccak_round(written, round_constant);
    keccak_round_inverted(inverted, before, round_constant);
    invert_lanes(inverted);
    for (size_t i = 0; i < 25; i++) {
        __CPROVER_assert(standard[i] == written[i], "the written-out round is FIPS 202's round");
        __CPROVER_assert(standard[i] == inverted[i],
                         "the inverted lanes round is FIPS 202's round on the inverted lanes");
        __CPROVER_assert(standard[i] == andn[i], "the ANDN form's round is FIPS 202's round");
    }

    uint64_t constants[24];
    for (unsigned round = 0; round < 24; round++) {
        constants[round] = reference_round_constant(round);
        __CPROVER_assert(RC[round] == constants[round],
                         "the table holds the shift register's constant");
    }
    uint64_t standard_zeros[25] = {0};
    uint64_t plain_zeros[25] = {0};
    uint64_t inverted_zeros[25] = {0};
    uint64_t our_zeros[25] = {0};
    uint64_t with_zeros[25] = {0};
    uint64_t scratch[25];
    uint64_t andn_zeros[25] = {0};
    uint64_t andn_scratch[25];
    reference_f1600(standard_zeros, constants);
    keccak_f1600_plain(plain_zeros);
    keccak_f1600_inverted(inverted_zeros);
    keccak_f1600(our_zeros);
    keccak_f1600_inverted_with(with_zeros, scratch);
    keccak_f1600_andn_with(andn_zeros, andn_scratch);
    for (size_t i = 0; i < 25; i++) {
        __CPROVER_assert(standard_zeros[i] == plain_zeros[i],
                         "24 plain rounds from the state of zeros are Keccak-f[1600]");
        __CPROVER_assert(standard_zeros[i] == inverted_zeros[i],
                         "24 inverted lanes rounds from the state of zeros are Keccak-f[1600]");
        __CPROVER_assert(standard_zeros[i] == our_zeros[i],
                         "the form keccak_f1600 picks is Keccak-f[1600]");
        __CPROVER_assert(standard_zeros[i] == with_zeros[i],
                         "24 inverted lanes rounds with the caller's scratch are Keccak-f[1600]");
        __CPROVER_assert(scratch[i] == 0, "the scratch state holds zeros after the 24 rounds");
        __CPROVER_assert(standard_zeros[i] == andn_zeros[i],
                         "24 ANDN form rounds from the state of zeros are Keccak-f[1600]");
        __CPROVER_assert(andn_scratch[i] == 0,
                         "the ANDN form's scratch state holds zeros after the 24 rounds");
    }
    return 0;
}
