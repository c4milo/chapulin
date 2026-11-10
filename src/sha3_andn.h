// The form of sha3.c's Keccak-f[1600] that sha3_hw.c's x86-64 copy runs for a session whose
// ch_cfg.cpu holds CH_CPU_BMI1 and CH_CPU_BMI2_ADX (docs/decisions.md 217). sha3.c alone includes
// this file, after rotate_left, which the text here calls. It includes sha3_inverted_lanes.h for
// KECCAK_CLOBBER_MEMORY. Every object compiles the form, so the sha3_round harness and
// bin/sha3_equiv_test hold it on every machine.
//
// The round is decision 216's round, from one state to a second one, with FIPS 202's chi in place
// of the chi of the six inverted lanes. ANDN, a BMI1 instruction, computes ~b & c to a third
// register, so each line of chi is one ANDN and one XOR, and no line takes a copy or a NOT. RORX,
// a BMI2 instruction, writes a rotation to a third register. The copy compiles this text under
// target("bmi,bmi2"), so the compiler writes the two instructions for the C below. No other
// object holds an instruction of either set.
#ifndef CH_SHA3_ANDN_H
#define CH_SHA3_ANDN_H

#include <stdint.h>

#include "ct.h"
#include "keccak_round_constants.h"
#include "sha3_inverted_lanes.h"

// keccak_round from in to out, with chi as FIPS 202 §3.2.4 writes it. in and out are two arrays.
//
// theta, rho and pi are keccak_round_inverted's lines: the five column parities, then one row of
// five lanes at a time, each t a lane of in with its column's d, and each b that t rotated. No lane
// is inverted, so chi is the standard's: a[x + 5y] = b[x + 5y] ^ (~b[x + 1 + 5y] & b[x + 2 + 5y]),
// with x + 1 and x + 2 modulo 5. The line that writes lane 0 XORs the round constant into it.
//
// The empty statements are keccak_round_inverted's, for its reasons: each makes the next lanes
// loads that the text names, and a store to out ends what the compiler knows of in.
//
// proof/sha3_round_harness.c proves this round equal to FIPS 202's round for every state and every
// round constant.
static inline __attribute__((always_inline)) void
keccak_round_andn(uint64_t out[25], const uint64_t in[25], uint64_t round_constant) {
    KECCAK_CLOBBER_MEMORY();
    uint64_t c0 = in[0] ^ in[5] ^ in[10] ^ in[15] ^ in[20];
    KECCAK_CLOBBER_MEMORY();
    uint64_t c1 = in[1] ^ in[6] ^ in[11] ^ in[16] ^ in[21];
    KECCAK_CLOBBER_MEMORY();
    uint64_t c2 = in[2] ^ in[7] ^ in[12] ^ in[17] ^ in[22];
    KECCAK_CLOBBER_MEMORY();
    uint64_t c3 = in[3] ^ in[8] ^ in[13] ^ in[18] ^ in[23];
    KECCAK_CLOBBER_MEMORY();
    uint64_t c4 = in[4] ^ in[9] ^ in[14] ^ in[19] ^ in[24];
    KECCAK_CLOBBER_MEMORY();
    uint64_t d0 = c4 ^ rotate_left(c1, 1);
    uint64_t d1 = c0 ^ rotate_left(c2, 1);
    uint64_t d2 = c1 ^ rotate_left(c3, 1);
    uint64_t d3 = c2 ^ rotate_left(c4, 1);
    uint64_t d4 = c3 ^ rotate_left(c0, 1);

    uint64_t t0 = in[0] ^ d0;
    uint64_t t1 = in[6] ^ d1;
    uint64_t t2 = in[12] ^ d2;
    uint64_t t3 = in[18] ^ d3;
    uint64_t t4 = in[24] ^ d4;
    uint64_t b0 = t0;
    uint64_t b1 = rotate_left(t1, 44);
    uint64_t b2 = rotate_left(t2, 43);
    uint64_t b3 = rotate_left(t3, 21);
    uint64_t b4 = rotate_left(t4, 14);
    out[0] = b0 ^ (~b1 & b2) ^ round_constant;
    out[1] = b1 ^ (~b2 & b3);
    out[2] = b2 ^ (~b3 & b4);
    out[3] = b3 ^ (~b4 & b0);
    out[4] = b4 ^ (~b0 & b1);

    uint64_t t5 = in[3] ^ d3;
    uint64_t t6 = in[9] ^ d4;
    uint64_t t7 = in[10] ^ d0;
    uint64_t t8 = in[16] ^ d1;
    uint64_t t9 = in[22] ^ d2;
    uint64_t b5 = rotate_left(t5, 28);
    uint64_t b6 = rotate_left(t6, 20);
    uint64_t b7 = rotate_left(t7, 3);
    uint64_t b8 = rotate_left(t8, 45);
    uint64_t b9 = rotate_left(t9, 61);
    out[5] = b5 ^ (~b6 & b7);
    out[6] = b6 ^ (~b7 & b8);
    out[7] = b7 ^ (~b8 & b9);
    out[8] = b8 ^ (~b9 & b5);
    out[9] = b9 ^ (~b5 & b6);

    uint64_t t10 = in[1] ^ d1;
    uint64_t t11 = in[7] ^ d2;
    uint64_t t12 = in[13] ^ d3;
    uint64_t t13 = in[19] ^ d4;
    uint64_t t14 = in[20] ^ d0;
    uint64_t b10 = rotate_left(t10, 1);
    uint64_t b11 = rotate_left(t11, 6);
    uint64_t b12 = rotate_left(t12, 25);
    uint64_t b13 = rotate_left(t13, 8);
    uint64_t b14 = rotate_left(t14, 18);
    out[10] = b10 ^ (~b11 & b12);
    out[11] = b11 ^ (~b12 & b13);
    out[12] = b12 ^ (~b13 & b14);
    out[13] = b13 ^ (~b14 & b10);
    out[14] = b14 ^ (~b10 & b11);

    uint64_t t15 = in[4] ^ d4;
    uint64_t t16 = in[5] ^ d0;
    uint64_t t17 = in[11] ^ d1;
    uint64_t t18 = in[17] ^ d2;
    uint64_t t19 = in[23] ^ d3;
    uint64_t b15 = rotate_left(t15, 27);
    uint64_t b16 = rotate_left(t16, 36);
    uint64_t b17 = rotate_left(t17, 10);
    uint64_t b18 = rotate_left(t18, 15);
    uint64_t b19 = rotate_left(t19, 56);
    out[15] = b15 ^ (~b16 & b17);
    out[16] = b16 ^ (~b17 & b18);
    out[17] = b17 ^ (~b18 & b19);
    out[18] = b18 ^ (~b19 & b15);
    out[19] = b19 ^ (~b15 & b16);

    uint64_t t20 = in[2] ^ d2;
    uint64_t t21 = in[8] ^ d3;
    uint64_t t22 = in[14] ^ d4;
    uint64_t t23 = in[15] ^ d0;
    uint64_t t24 = in[21] ^ d1;
    uint64_t b20 = rotate_left(t20, 62);
    uint64_t b21 = rotate_left(t21, 55);
    uint64_t b22 = rotate_left(t22, 39);
    uint64_t b23 = rotate_left(t23, 41);
    uint64_t b24 = rotate_left(t24, 2);
    out[20] = b20 ^ (~b21 & b22);
    out[21] = b21 ^ (~b22 & b23);
    out[22] = b22 ^ (~b23 & b24);
    out[23] = b23 ^ (~b24 & b20);
    out[24] = b24 ^ (~b20 & b21);
}

// The 24 rounds, two at a time from a to scratch and back, so the last round writes a and scratch
// holds the state before that round. Out of line for keccak_rounds_inverted's reason.
static __attribute__((noinline)) void keccak_rounds_andn(uint64_t a[25], uint64_t scratch[25]) {
    for (int round = 0; round < 24; round += 2) {
        keccak_round_andn(scratch, a, RC[round]);
        keccak_round_andn(a, scratch, RC[round + 1]);
    }
}

// Keccak-f[1600] on a, with scratch as the second state. scratch holds a state of the permutation
// after the rounds, so the call writes zeros over it.
static void keccak_f1600_andn_with(uint64_t a[25], uint64_t scratch[25]) {
    keccak_rounds_andn(a, scratch);
    ct_wipe(scratch, 25 * sizeof(uint64_t));
}

// Keccak-f[1600] on a, with the scratch state on this frame.
static void keccak_f1600_andn(uint64_t a[25]) {
    uint64_t scratch[25];
    keccak_f1600_andn_with(a, scratch);
}

#endif
