// The inverted lanes form of sha3.c's Keccak-f[1600] (docs/decisions.md
// 195). sha3.c alone includes this file, after rotate_left, which the
// text here calls.
//
// Between rounds the state keeps six lanes inverted, each bit flipped:
// a[1], a[2], a[8], a[12], a[17] and a[20], the lanes (1, 0), (2, 0),
// (3, 1), (2, 2), (2, 3) and (0, 4). x86-64 has no AND-NOT instruction
// before BMI1, so keccak_round's chi costs a NOT and an AND for each
// lane. The chi below takes five NOTs a round in place of 25.
#ifndef CH_SHA3_INVERTED_LANES_H
#define CH_SHA3_INVERTED_LANES_H

#include <stdint.h>

#include "keccak_round_constants.h"

// keccak_round, with the chi that the six inverted lanes permit. theta,
// rho and pi are keccak_round's lines, unchanged.
//
// theta. A column parity is inverted when its column holds an odd count
// of inverted lanes. Columns 0 to 3 hold one or three, and column 4
// holds none, so c0 to c3 are inverted. d[x] XORs c[x - 1] and
// c[x + 1], so d0 and d3 are inverted. The 25 XORs then invert each
// lane of columns 0 and 3 once more. No instruction does this work: the
// chi lines read each b as stored, inverted or not.
//
// chi. Each line writes its lane inverted if the lane is one of the six,
// and as is if not. ~b & c is b & c when b is stored inverted and c is
// not. It is ~(b | c) when c is stored inverted and b is not, and the
// outer NOT then becomes the lane's own inversion. Where neither form
// fits, the line takes a NOT, one in each row of five lanes.
//
// proof/sha3_round_harness.c proves this round equal to FIPS 202's round,
// with the six lanes inverted before and after, for every state and
// every round constant.
static void keccak_round_inverted(uint64_t a[25], uint64_t round_constant) {
    uint64_t c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
    uint64_t c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
    uint64_t c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
    uint64_t c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
    uint64_t c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
    uint64_t d0 = c4 ^ rotate_left(c1, 1);
    uint64_t d1 = c0 ^ rotate_left(c2, 1);
    uint64_t d2 = c1 ^ rotate_left(c3, 1);
    uint64_t d3 = c2 ^ rotate_left(c4, 1);
    uint64_t d4 = c3 ^ rotate_left(c0, 1);

    a[0] ^= d0;
    a[5] ^= d0;
    a[10] ^= d0;
    a[15] ^= d0;
    a[20] ^= d0;
    a[1] ^= d1;
    a[6] ^= d1;
    a[11] ^= d1;
    a[16] ^= d1;
    a[21] ^= d1;
    a[2] ^= d2;
    a[7] ^= d2;
    a[12] ^= d2;
    a[17] ^= d2;
    a[22] ^= d2;
    a[3] ^= d3;
    a[8] ^= d3;
    a[13] ^= d3;
    a[18] ^= d3;
    a[23] ^= d3;
    a[4] ^= d4;
    a[9] ^= d4;
    a[14] ^= d4;
    a[19] ^= d4;
    a[24] ^= d4;

    uint64_t b0 = a[0];
    uint64_t b1 = rotate_left(a[6], 44);
    uint64_t b2 = rotate_left(a[12], 43);
    uint64_t b3 = rotate_left(a[18], 21);
    uint64_t b4 = rotate_left(a[24], 14);

    uint64_t b5 = rotate_left(a[3], 28);
    uint64_t b6 = rotate_left(a[9], 20);
    uint64_t b7 = rotate_left(a[10], 3);
    uint64_t b8 = rotate_left(a[16], 45);
    uint64_t b9 = rotate_left(a[22], 61);

    uint64_t b10 = rotate_left(a[1], 1);
    uint64_t b11 = rotate_left(a[7], 6);
    uint64_t b12 = rotate_left(a[13], 25);
    uint64_t b13 = rotate_left(a[19], 8);
    uint64_t b14 = rotate_left(a[20], 18);

    uint64_t b15 = rotate_left(a[4], 27);
    uint64_t b16 = rotate_left(a[5], 36);
    uint64_t b17 = rotate_left(a[11], 10);
    uint64_t b18 = rotate_left(a[17], 15);
    uint64_t b19 = rotate_left(a[23], 56);

    uint64_t b20 = rotate_left(a[2], 62);
    uint64_t b21 = rotate_left(a[8], 55);
    uint64_t b22 = rotate_left(a[14], 39);
    uint64_t b23 = rotate_left(a[15], 41);
    uint64_t b24 = rotate_left(a[21], 2);

    uint64_t not_b2 = ~b2;
    uint64_t not_b9 = ~b9;
    uint64_t not_b13 = ~b13;
    uint64_t not_b18 = ~b18;
    uint64_t not_b21 = ~b21;

    a[0] = b0 ^ (b1 | b2);
    a[1] = b1 ^ (not_b2 | b3);
    a[2] = b2 ^ (b3 & b4);
    a[3] = b3 ^ (b4 | b0);
    a[4] = b4 ^ (b0 & b1);
    a[5] = b5 ^ (b6 | b7);
    a[6] = b6 ^ (b7 & b8);
    a[7] = b7 ^ (b8 | not_b9);
    a[8] = b8 ^ (b9 | b5);
    a[9] = b9 ^ (b5 & b6);
    a[10] = b10 ^ (b11 | b12);
    a[11] = b11 ^ (b12 & b13);
    a[12] = b12 ^ (not_b13 & b14);
    a[13] = not_b13 ^ (b14 | b10);
    a[14] = b14 ^ (b10 & b11);
    a[15] = b15 ^ (b16 & b17);
    a[16] = b16 ^ (b17 | b18);
    a[17] = b17 ^ (not_b18 | b19);
    a[18] = not_b18 ^ (b19 & b15);
    a[19] = b19 ^ (b15 | b16);
    a[20] = b20 ^ (not_b21 & b22);
    a[21] = not_b21 ^ (b22 | b23);
    a[22] = b22 ^ (b23 & b24);
    a[23] = b23 ^ (b24 | b20);
    a[24] = b24 ^ (b20 & b21);

    a[0] ^= round_constant;
}

// Inverts the six lanes that keccak_round_inverted keeps inverted. A
// second call undoes the first.
static void invert_lanes(uint64_t a[25]) {
    a[1] = ~a[1];
    a[2] = ~a[2];
    a[8] = ~a[8];
    a[12] = ~a[12];
    a[17] = ~a[17];
    a[20] = ~a[20];
}

// Keccak-f[1600]: the six lanes inverted, the 24 rounds, and the six
// lanes inverted again, so the state before and after holds the
// standard's lanes.
static void keccak_f1600_inverted(uint64_t a[25]) {
    invert_lanes(a);
    for (int round = 0; round < 24; round++) {
        keccak_round_inverted(a, RC[round]);
    }
    invert_lanes(a);
}

#endif
