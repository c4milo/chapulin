// The inverted lanes form of sha3.c's Keccak-f[1600] (docs/decisions.md
// 195 and 216). sha3.c alone includes this file, after rotate_left, which
// the text here calls.
//
// Between rounds the state keeps six lanes inverted, each bit flipped:
// a[1], a[2], a[8], a[12], a[17] and a[20], the lanes (1, 0), (2, 0),
// (3, 1), (2, 2), (2, 3) and (0, 4). x86-64 has no AND-NOT instruction
// before BMI1, so keccak_round's chi costs a NOT and an AND for each
// lane. The chi below takes five NOTs a round in place of 25.
//
// A round here reads one state and writes a second one, where keccak_round
// works in place on one array. The 24 rounds go from the caller's state to
// a scratch state and back, 12 times. The reason is the compiler's use of
// registers. x86-64 has 15 general registers, and a round in place holds
// 25 lanes and more as values. gcc 13 and clang then choose which values
// they keep in stack slots, and write a move, a load or a store for each
// choice. With two states each lane is in memory at a place the text
// names, and a row of chi needs five lanes and the five values of theta
// in registers.
#ifndef CH_SHA3_INVERTED_LANES_H
#define CH_SHA3_INVERTED_LANES_H

#include <stdint.h>

#include "ct.h"
#include "keccak_round_constants.h"

// An empty statement that the compiler takes as a write to all memory. It
// emits no instruction. After it the compiler holds no lane's value from
// an earlier load or store, so it loads each lane where the text below
// reads it. Only an x86-64 host object compiles the statement, because
// only that object runs this form (sha3.c's SHA3_INVERTED_LANES). The
// proofs and bin/sha3_equiv_test compile the same C without it.
#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)
#define KECCAK_CLOBBER_MEMORY() __asm__ volatile("" ::: "memory")
#else
#define KECCAK_CLOBBER_MEMORY() ((void)0)
#endif

// keccak_round from in to out, with the chi that the six inverted lanes
// permit. in and out are two arrays.
//
// theta. A column parity is inverted when its column holds an odd count
// of inverted lanes. Columns 0 to 3 hold one or three, and column 4
// holds none, so c0 to c3 are inverted. d[x] XORs c[x - 1] and
// c[x + 1], so d0 and d3 are inverted. The XOR of d into a lane then
// inverts each lane of columns 0 and 3 once more. No instruction does
// this work: the chi lines read each b as it is, inverted or not.
//
// rho and pi. The five lanes of a row are keccak_round's b lines, five at
// a time: each t is a lane of in with its column's d, and each b is that t
// rotated. Each rotation takes a t and no expression, for the reason
// keccak_round gives for theta.
//
// chi. Each line writes its lane inverted if the lane is one of the six,
// and as is if not. ~b & c is b & c when b is inverted and c is not. It
// is ~(b | c) when c is inverted and b is not, and the outer NOT then
// becomes the lane's own inversion. Where neither form fits, the line
// takes a NOT, one in each row of five lanes.
//
// The order of a row's five lines. An AND or an OR of x86-64 writes its
// result over one of its two operands. So a line needs a copy of a lane,
// unless one of the two lanes it joins is read by no later line. The
// first two lines of each row take a copy. Each of the last three joins a
// lane that no later line reads, and the row's NOT stands after the last
// line that reads its lane as it is. With the lines in the order of the
// lanes, gcc 13 wrote four copies a row and clang three.
//
// iota. The line that writes lane 0 XORs the round constant into it.
//
// The empty statements. The first one ends what the compiler knows of the
// stores of the round before. Without it gcc 13 kept each lane it stored
// as a value for this round, and stored the lane once more in a stack
// slot. The one after each column's parity keeps a compiler from one
// 16-byte load of two lanes for two columns, which clang 18 wrote: the
// round before stored each lane 8 bytes at a time, and a load of two such
// stores waits for both. The last of them also makes the rows load their
// lanes again. Without it clang kept some of the lanes it loaded for the
// parities in stack slots of its choice. A store to out ends what the
// compiler knows of in, because it cannot prove that the two arrays
// differ, so each row loads its five lanes after the row before it.
//
// proof/sha3_round_harness.c proves this round equal to FIPS 202's round,
// with the six lanes inverted before and after, for every state and
// every round constant.
static inline __attribute__((always_inline)) void
keccak_round_inverted(uint64_t out[25], const uint64_t in[25], uint64_t round_constant) {
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
    out[0] = b0 ^ (b1 | b2) ^ round_constant;
    out[4] = b4 ^ (b0 & b1);
    out[3] = b3 ^ (b4 | b0);
    out[2] = b2 ^ (b3 & b4);
    uint64_t not_b2 = ~b2;
    out[1] = b1 ^ (not_b2 | b3);

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
    out[5] = b5 ^ (b6 | b7);
    out[9] = b9 ^ (b5 & b6);
    out[8] = b8 ^ (b9 | b5);
    uint64_t not_b9 = ~b9;
    out[7] = b7 ^ (b8 | not_b9);
    out[6] = b6 ^ (b7 & b8);

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
    out[10] = b10 ^ (b11 | b12);
    out[11] = b11 ^ (b12 & b13);
    uint64_t not_b13 = ~b13;
    out[14] = b14 ^ (b10 & b11);
    out[13] = not_b13 ^ (b14 | b10);
    out[12] = b12 ^ (not_b13 & b14);

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
    out[15] = b15 ^ (b16 & b17);
    out[16] = b16 ^ (b17 | b18);
    uint64_t not_b18 = ~b18;
    out[19] = b19 ^ (b15 | b16);
    out[18] = not_b18 ^ (b19 & b15);
    out[17] = b17 ^ (not_b18 | b19);

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
    out[24] = b24 ^ (b20 & b21);
    uint64_t not_b21 = ~b21;
    out[20] = b20 ^ (not_b21 & b22);
    out[23] = b23 ^ (b24 | b20);
    out[22] = b22 ^ (b23 & b24);
    out[21] = not_b21 ^ (b22 | b23);
}

// Inverts the six lanes that keccak_round_inverted keeps inverted. A
// second call undoes the first. The empty statement keeps a[1] and a[2]
// two 8-byte loads: the last round stores each lane 8 bytes at a time, and
// clang loaded the two as 16 bytes.
static void invert_lanes(uint64_t a[25]) {
    a[1] = ~a[1];
    KECCAK_CLOBBER_MEMORY();
    a[2] = ~a[2];
    a[8] = ~a[8];
    a[12] = ~a[12];
    a[17] = ~a[17];
    a[20] = ~a[20];
}

// The 24 rounds on a state whose six lanes are inverted. Each two rounds
// go from a to scratch and back, so the last round writes a, and scratch
// holds the state before that round.
//
// The function is out of line, so a and scratch are two pointers of which
// the compiler knows nothing, and a store through one ends what it knows
// of the other. Inline in the function that owns scratch, clang wrote
// eight more instructions a round, and gcc 13 wrote the same count in both
// places (docs/decisions.md 216).
static __attribute__((noinline)) void keccak_rounds_inverted(uint64_t a[25], uint64_t scratch[25]) {
    for (int round = 0; round < 24; round += 2) {
        keccak_round_inverted(scratch, a, RC[round]);
        keccak_round_inverted(a, scratch, RC[round + 1]);
    }
}

// Keccak-f[1600] on a, with scratch as the second state: the six lanes
// inverted, the 24 rounds, and the six lanes inverted again, so a holds
// the standard's lanes before and after. scratch holds a state of the
// permutation after the rounds, so the call writes zeros over it.
static void keccak_f1600_inverted_with(uint64_t a[25], uint64_t scratch[25]) {
    invert_lanes(a);
    keccak_rounds_inverted(a, scratch);
    invert_lanes(a);
    ct_wipe(scratch, 25 * sizeof(uint64_t));
}

// Keccak-f[1600] on a, with the scratch state on this frame.
static void keccak_f1600_inverted(uint64_t a[25]) {
    uint64_t scratch[25];
    keccak_f1600_inverted_with(a, scratch);
}

#endif
