// FIPS 180-4 §6.4.2 as the standard writes it, for the two harnesses that
// hold sha512_compress_blocks.c's steps to it:
// sha512_compress_blocks_steps_harness.c and
// sha512_compress_blocks_advancing_harness.c. Each includes this header
// after the file, so the file's static steps are in scope beside these.
//
// The forms here share no text with the file: the four sigma functions are
// the standard's three terms each, Ch and Maj its two equations, a round
// moves the eight working variables, and the message schedule reads a
// ring of sixteen words by an index taken modulo 16 with the remainder
// operator.
#ifndef CH_PROOF_SHA512_COMPRESS_BLOCKS_STEPS_H
#define CH_PROOF_SHA512_COMPRESS_BLOCKS_STEPS_H

#include <stddef.h>
#include <stdint.h>

uint64_t nondet_u64(void);

static uint64_t standard_rotate(uint64_t x, unsigned r) {
    return (x >> r) | (x << (64 - r));
}

// FIPS 180-4 §6.4.2 step 3, once: v[0] to v[7] are a to h.
static void standard_round(uint64_t v[8], uint64_t word_plus_constant) {
    uint64_t a = v[0];
    uint64_t e = v[4];
    uint64_t s1 = standard_rotate(e, 14) ^ standard_rotate(e, 18) ^ standard_rotate(e, 41);
    uint64_t s0 = standard_rotate(a, 28) ^ standard_rotate(a, 34) ^ standard_rotate(a, 39);
    uint64_t t1 = v[7] + s1 + ((e & v[5]) ^ (~e & v[6])) + word_plus_constant;
    uint64_t t2 = s0 + ((a & v[1]) ^ (a & v[2]) ^ (v[1] & v[2]));
    v[7] = v[6];
    v[6] = v[5];
    v[5] = v[4];
    v[4] = v[3] + t1;
    v[3] = v[2];
    v[2] = v[1];
    v[1] = v[0];
    v[0] = t1 + t2;
}

// FIPS 180-4 §6.4.2 step 1 on a ring that holds W[t - 16] to W[t - 1] with
// W[t - 16] at index i: W[t].
static uint64_t standard_word(const uint64_t ring[16], size_t i) {
    uint64_t fifteen_back = ring[(i + 1) % 16];
    uint64_t two_back = ring[(i + 14) % 16];
    uint64_t s0 =
        standard_rotate(fifteen_back, 1) ^ standard_rotate(fifteen_back, 8) ^ (fifteen_back >> 7);
    uint64_t s1 = standard_rotate(two_back, 19) ^ standard_rotate(two_back, 61) ^ (two_back >> 6);
    return ring[i] + s0 + ring[(i + 9) % 16] + s1;
}

// The eight working variables a to h in v, and b ^ c, as the file's
// rounds take them.
static working_variables variables_of(const uint64_t v[8]) {
    working_variables out = {v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[1] ^ v[2]};
    return out;
}

#endif
