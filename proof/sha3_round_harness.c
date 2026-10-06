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
// Together: the round is the standard's for every input, and
// keccak_f1600 applies it 24 times with the standard's constants in the
// standard's order, so the permutation is the standard's.
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
    reference_round(standard, round_constant);
    keccak_round(written, round_constant);
    for (size_t i = 0; i < 25; i++) {
        __CPROVER_assert(standard[i] == written[i], "the written-out round is FIPS 202's round");
    }

    uint64_t constants[24];
    for (unsigned round = 0; round < 24; round++) {
        constants[round] = reference_round_constant(round);
        __CPROVER_assert(RC[round] == constants[round],
                         "the table holds the shift register's constant");
    }
    uint64_t standard_zeros[25] = {0};
    uint64_t our_zeros[25] = {0};
    reference_f1600(standard_zeros, constants);
    keccak_f1600(our_zeros);
    for (size_t i = 0; i < 25; i++) {
        __CPROVER_assert(standard_zeros[i] == our_zeros[i],
                         "24 rounds from the state of zeros are Keccak-f[1600]");
    }
    return 0;
}
