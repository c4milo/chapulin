// FIPS 202 as the standard writes it, for the checks that hold sha3.c to
// it: each step of a round as its algorithm states it, with loops over a
// lane's column x and row y; the rho offsets and the round constants
// computed by the standard's rules and read from no table; and a sponge
// that moves one byte at a time.
//
// sha3.c writes the round out lane by lane, reads its constants from a
// table and moves eight bytes at a time. A reference that does none of
// the three is what makes "the same bytes" a claim and not a
// restatement. proof/sha3_round_harness.c reads the round and the
// constants, and test/sha3_equiv_test.c reads all of it.
//
// No library object compiles this file, and nothing in it is written for
// speed or for secret inputs.
#ifndef CH_PROOF_SHA3_REFERENCE_H
#define CH_PROOF_SHA3_REFERENCE_H

#include <stddef.h>
#include <stdint.h>

// A state is 25 lanes of 64 bits: lane (x, y) is a[x + 5 * y], and bit z
// of a lane is the bit of weight 2^z (FIPS 202 §3.1.2).

// r may be 0, which is lane (0, 0)'s offset.
static uint64_t reference_rotate_left(uint64_t x, unsigned r) {
    return (x << r) | (x >> ((64 - r) & 63));
}

// theta, Algorithm 1: C[x] is the parity of column x, and D[x] = C[x - 1]
// ^ C[x + 1] with its bits moved up one place.
static void reference_theta(uint64_t out[25], const uint64_t in[25]) {
    uint64_t c[5];
    for (int x = 0; x < 5; x++) {
        c[x] = in[x] ^ in[x + 5] ^ in[x + 10] ^ in[x + 15] ^ in[x + 20];
    }
    for (int x = 0; x < 5; x++) {
        uint64_t d = c[(x + 4) % 5] ^ reference_rotate_left(c[(x + 1) % 5], 1);
        for (int y = 0; y < 5; y++) {
            out[x + 5 * y] = in[x + 5 * y] ^ d;
        }
    }
}

// rho, Algorithm 2: lane (0, 0) stays, and the walk (x, y) = (1, 0), then
// (y, 2x + 3y), visits the other 24 lanes, rotating the lane of step t
// by (t + 1)(t + 2) / 2 places.
static void reference_rho(uint64_t out[25], const uint64_t in[25]) {
    out[0] = in[0];
    int x = 1;
    int y = 0;
    for (int t = 0; t < 24; t++) {
        unsigned offset = (unsigned)((t + 1) * (t + 2) / 2) % 64;
        out[x + 5 * y] = reference_rotate_left(in[x + 5 * y], offset);
        int next_y = (2 * x + 3 * y) % 5;
        x = y;
        y = next_y;
    }
}

// pi, Algorithm 3: A'[x, y] = A[(x + 3y) mod 5, x].
static void reference_pi(uint64_t out[25], const uint64_t in[25]) {
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            out[x + 5 * y] = in[(x + 3 * y) % 5 + 5 * x];
        }
    }
}

// chi, Algorithm 4: A'[x, y] = A[x, y] ^ (~A[x + 1, y] & A[x + 2, y]).
static void reference_chi(uint64_t out[25], const uint64_t in[25]) {
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            out[x + 5 * y] = in[x + 5 * y] ^ (~in[(x + 1) % 5 + 5 * y] & in[(x + 2) % 5 + 5 * y]);
        }
    }
}

// rc(t), Algorithm 5: one bit of a round constant, from a shift register
// of eight bits. r[0..7] is the standard's R, and r[8] holds the bit that
// step 3a makes room for and step 3f drops.
static unsigned reference_rc(unsigned t) {
    unsigned r[9] = {1, 0, 0, 0, 0, 0, 0, 0, 0};
    for (unsigned i = 1; i <= t % 255; i++) {
        for (int k = 8; k > 0; k--) {
            r[k] = r[k - 1];
        }
        r[0] = 0;
        r[0] ^= r[8];
        r[4] ^= r[8];
        r[5] ^= r[8];
        r[6] ^= r[8];
    }
    return r[0];
}

// Algorithm 6, steps 2 and 3: bit 2^j - 1 of round ir's constant is
// rc(j + 7 * ir), for j from 0 to 6.
static uint64_t reference_round_constant(unsigned round) {
    uint64_t constant = 0;
    for (unsigned j = 0; j <= 6; j++) {
        constant |= (uint64_t)reference_rc(j + 7 * round) << ((1U << j) - 1);
    }
    return constant;
}

// Rnd(A, ir) = iota(chi(pi(rho(theta(A)))), ir), §3.3. iota XORs the
// round's constant into lane (0, 0).
static void reference_round(uint64_t a[25], uint64_t round_constant) {
    uint64_t after_theta[25];
    uint64_t after_rho[25];
    uint64_t after_pi[25];
    reference_theta(after_theta, a);
    reference_rho(after_rho, after_theta);
    reference_pi(after_pi, after_rho);
    reference_chi(a, after_pi);
    a[0] ^= round_constant;
}

// Keccak-f[1600] is rounds 0 to 23 (§3.4), given their constants.
static void reference_f1600(uint64_t a[25], const uint64_t round_constants[24]) {
    for (unsigned round = 0; round < 24; round++) {
        reference_round(a, round_constants[round]);
    }
}

// The sponge of §4, a byte at a time. Byte i of a block is byte i % 8 of
// lane i / 8, counted from the lane's low end (§3.1.2).
typedef struct {
    uint64_t lane[25];
    uint64_t round_constants[24];
    size_t rate; // bytes in a block: 200 less twice the security strength
    size_t pos;  // the next byte of the block to write or to read
} sha3_reference;

static void reference_init(sha3_reference *s, size_t rate) {
    for (int i = 0; i < 25; i++) {
        s->lane[i] = 0;
    }
    for (unsigned round = 0; round < 24; round++) {
        s->round_constants[round] = reference_round_constant(round);
    }
    s->rate = rate;
    s->pos = 0;
}

static void reference_absorb(sha3_reference *s, const uint8_t *in, size_t n) {
    for (size_t i = 0; i < n; i++) {
        s->lane[s->pos / 8] ^= (uint64_t)in[i] << (8 * (s->pos % 8));
        s->pos++;
        if (s->pos == s->rate) {
            reference_f1600(s->lane, s->round_constants);
            s->pos = 0;
        }
    }
}

// pad10*1 after the function's own suffix (§B.2): the suffix and the
// first pad bit are `domain`, 0x06 for SHA-3 and 0x1f for SHAKE, and the
// last pad bit is the top bit of the block's last byte.
static void reference_pad(sha3_reference *s, uint8_t domain) {
    s->lane[s->pos / 8] ^= (uint64_t)domain << (8 * (s->pos % 8));
    s->lane[(s->rate - 1) / 8] ^= (uint64_t)0x80 << (8 * ((s->rate - 1) % 8));
    reference_f1600(s->lane, s->round_constants);
    s->pos = 0;
}

static void reference_squeeze(sha3_reference *s, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (s->pos == s->rate) {
            reference_f1600(s->lane, s->round_constants);
            s->pos = 0;
        }
        out[i] = (uint8_t)(s->lane[s->pos / 8] >> (8 * (s->pos % 8)));
        s->pos++;
    }
}

#endif
