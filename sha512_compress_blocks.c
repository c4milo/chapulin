// The SHA-512 compression function (FIPS 180-4 §6.4.2) over whole blocks, in plain C, which a
// host object holds (sha512_compress_blocks.h). It uses no intrinsic and no instruction-set
// attribute. Its operations are 64-bit adds, rotates, shifts and bitwise logic, which every
// arm64 and x86-64 CPU runs in the same time for every operand, it reads no table at an index
// a word decides, and it branches on the block count alone. So no ch_cfg.cpu bit picks it, and
// every session of a host object runs it (docs/decisions.md 127).
//
// sha512_compress.c stays the reference. This file computes the same state and differs from
// it in seven ways, each of which docs/decisions.md 127 measures:
//
//   a block's words are read by one expression each, which compiles to a load and a byte swap;
//   the message schedule is a ring of sixteen words, where the reference fills eighty first;
//   each word of the ring is replaced by the word sixteen after it in the round that takes
//   that word, so the schedule's work lies between the rounds';
//   the rounds are written out sixteen to a pass with the working variables' roles renamed, so
//   no value moves, where the reference moves seven variables a round;
//   Ch and Maj are written in three operations each;
//   the four sigma functions are written as nested rotates, which need one copy of their
//   operand where the standard's three terms need three;
//   one call absorbs a count of blocks, and reads the working variables from the state once.
//
// What a call computes from the message it leaves in its own frame: the ring's sixteen words,
// and whichever working variables the compiler wrote to stack slots of its own, which no
// ct_wipe can name. So the caller wipes the stack below itself after the call (sha512.c).
//
// proof/sha512_compress_blocks_harness.c proves the function reads and writes inside its
// arrays over any state and zero to two blocks, and proof/sha512_compress_blocks_steps_harness.c
// proves each step below against FIPS 180-4's own form over every input. That the steps in the
// order this file calls them compute sha512_compress's state rests on bin/sha2_equiv_test and
// on the published vectors (docs/verification.md, "SHA-512 in a host object").
#include "sha512_compress_blocks.h"

#ifdef CH_CPU_RUNTIME

#include "sha512_round_constants.h"

static inline uint64_t rotate_right(uint64_t x, unsigned r) {
    return (x >> r) | (x << (64 - r));
}

// FIPS 180-4 §4.1.3, equations 4.10 to 4.13, which the standard writes as three terms each:
//
//   upper_sigma0(x) = rotate_right(x, 28) ^ rotate_right(x, 34) ^ rotate_right(x, 39)
//   upper_sigma1(x) = rotate_right(x, 14) ^ rotate_right(x, 18) ^ rotate_right(x, 41)
//   lower_sigma0(x) = rotate_right(x, 1) ^ rotate_right(x, 8) ^ (x >> 7)
//   lower_sigma1(x) = rotate_right(x, 19) ^ rotate_right(x, 61) ^ (x >> 6)
//
// A rotate of an exclusive OR is the exclusive OR of the rotates, so each function below is the
// same value with every rotate applied to the exclusive OR before it: upper_sigma0's three
// rotates turn x by 5 + 6 + 28 = 39, by 6 + 28 = 34 and by 28. Written this way each rotate
// overwrites its operand. An x86-64 rotate does that anyway, so a compiler without RORX copies
// x once where the three terms have it copy x three times (docs/decisions.md 127).
static inline uint64_t upper_sigma0(uint64_t x) {
    return rotate_right(rotate_right(rotate_right(x, 5) ^ x, 6) ^ x, 28);
}

// 23 + 4 + 14 = 41, 4 + 14 = 18, and 14.
static inline uint64_t upper_sigma1(uint64_t x) {
    return rotate_right(rotate_right(rotate_right(x, 23) ^ x, 4) ^ x, 14);
}

// 7 + 1 = 8, and 1.
static inline uint64_t lower_sigma0(uint64_t x) {
    return rotate_right(rotate_right(x, 7) ^ x, 1) ^ (x >> 7);
}

// 42 + 19 = 61, and 19.
static inline uint64_t lower_sigma1(uint64_t x) {
    return rotate_right(rotate_right(x, 42) ^ x, 19) ^ (x >> 6);
}

// Ch (equation 4.8) in three operations: where a bit of e is 1 the result is g ^ f ^ g, which
// is f, and where it is 0 the result is g.
static inline uint64_t choice(uint64_t e, uint64_t f, uint64_t g) {
    return g ^ (e & (f ^ g));
}

// Maj (equation 4.9) from a ^ b and b ^ c: where a and b agree the result is b, and where they
// differ it is b ^ b ^ c, which is c, the vote of the third.
static inline uint64_t majority(uint64_t b, uint64_t a_xor_b, uint64_t b_xor_c) {
    return b ^ (a_xor_b & b_xor_c);
}

// One word of the message, most significant byte first (FIPS 180-4 §3.1). gcc and clang
// compile the expression to one 8-byte load and a byte swap on a little-endian target, where
// gcc 13 compiles sha512_compress.c's loop over the eight bytes to that loop.
static inline uint64_t load_word(const uint8_t p[8]) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

// A word of the ring or of the caller's state read from memory at the point of use, as
// sha512_hw.c's kept reads a field. The read goes through a volatile pointer, so the compiler
// loads the word from where it lies each time. Without it gcc and clang for x86-64, which has
// fifteen registers for twenty-five words, keep a second copy of the ring and of the state in
// stack slots of their own and write each new word twice.
static inline uint64_t kept(const uint64_t *word) {
    const volatile uint64_t *in_memory = word;
    return *in_memory;
}

// The eight working variables of FIPS 180-4 §6.4.2 step 2, and b ^ c, which majority reads.
typedef struct {
    uint64_t a;
    uint64_t b;
    uint64_t c;
    uint64_t d;
    uint64_t e;
    uint64_t f;
    uint64_t g;
    uint64_t h;
    uint64_t b_xor_c;
} working_variables;

// One round (FIPS 180-4 §6.4.2 step 3) that moves no value. Its arguments name the working
// variables by the role each has in this round, and c is read through *b_xor_c alone. The round
// writes two variables: it adds T1 to the one at d, which is the next round's e, and writes
// T1 + T2 over the one at h, which is the next round's a. The other six keep their values and
// take the next role: this round's a is the next round's b, b is c, c is d, e is f, f is g and
// g is h. It leaves a ^ b in *b_xor_c, which is the next round's b ^ c.
static inline __attribute__((always_inline)) void one_round(uint64_t a, uint64_t b, uint64_t *d,
                                                            uint64_t e, uint64_t f, uint64_t g,
                                                            uint64_t *h, uint64_t *b_xor_c,
                                                            uint64_t word_plus_constant) {
    uint64_t a_xor_b = a ^ b;
    uint64_t t1 = *h + upper_sigma1(e) + choice(e, f, g) + word_plus_constant;
    uint64_t t2 = upper_sigma0(a) + majority(b, a_xor_b, *b_xor_c);
    *d += t1;
    *h = t1 + t2;
    *b_xor_c = a_xor_b;
}

// The message schedule is a ring of sixteen words: ring[t mod 16] holds W[t] for the last
// sixteen values of t. W[t] is made from the words 16, 15, 7 and 2 before it (FIPS 180-4
// §6.4.2 step 1), which are at i, i + 1, i + 9 and i + 14 mod 16 for i = t mod 16, and it
// replaces the word 16 before it, which no later word reads. This writes W[t] over ring[i] and
// returns it.
static inline __attribute__((always_inline)) uint64_t next_word(uint64_t ring[16], size_t i) {
    uint64_t fifteen_back = kept(&ring[(i + 1) & 15]);
    uint64_t two_back = kept(&ring[(i + 14) & 15]);
    uint64_t word = kept(&ring[i]) + lower_sigma0(fifteen_back) + kept(&ring[(i + 9) & 15]) +
                    lower_sigma1(two_back);
    ring[i] = word;
    return word;
}

// Rounds 0 to 15, eight to a call: each takes a word of the block as it lies in the ring. The
// eight calls name the same eight variables with each role moved on by one place, and bring
// every role back to where it began.
static inline __attribute__((always_inline)) void
eight_rounds(working_variables *v, const uint64_t k[8], const uint64_t w[8]) {
    uint64_t *b_xor_c = &v->b_xor_c;
    one_round(v->a, v->b, &v->d, v->e, v->f, v->g, &v->h, b_xor_c, k[0] + kept(&w[0]));
    one_round(v->h, v->a, &v->c, v->d, v->e, v->f, &v->g, b_xor_c, k[1] + kept(&w[1]));
    one_round(v->g, v->h, &v->b, v->c, v->d, v->e, &v->f, b_xor_c, k[2] + kept(&w[2]));
    one_round(v->f, v->g, &v->a, v->b, v->c, v->d, &v->e, b_xor_c, k[3] + kept(&w[3]));
    one_round(v->e, v->f, &v->h, v->a, v->b, v->c, &v->d, b_xor_c, k[4] + kept(&w[4]));
    one_round(v->d, v->e, &v->g, v->h, v->a, v->b, &v->c, b_xor_c, k[5] + kept(&w[5]));
    one_round(v->c, v->d, &v->f, v->g, v->h, v->a, &v->b, b_xor_c, k[6] + kept(&w[6]));
    one_round(v->b, v->c, &v->e, v->f, v->g, v->h, &v->a, b_xor_c, k[7] + kept(&w[7]));
}

// Rounds 16 to 79, eight to a call: each first replaces ring[i] by the word sixteen after it,
// and takes that word. i is 0 or 8.
static inline __attribute__((always_inline)) void
eight_rounds_advancing(working_variables *v, const uint64_t k[8], uint64_t ring[16], size_t i) {
    uint64_t *b_xor_c = &v->b_xor_c;
    one_round(v->a, v->b, &v->d, v->e, v->f, v->g, &v->h, b_xor_c, k[0] + next_word(ring, i));
    one_round(v->h, v->a, &v->c, v->d, v->e, v->f, &v->g, b_xor_c, k[1] + next_word(ring, i + 1));
    one_round(v->g, v->h, &v->b, v->c, v->d, v->e, &v->f, b_xor_c, k[2] + next_word(ring, i + 2));
    one_round(v->f, v->g, &v->a, v->b, v->c, v->d, &v->e, b_xor_c, k[3] + next_word(ring, i + 3));
    one_round(v->e, v->f, &v->h, v->a, v->b, v->c, &v->d, b_xor_c, k[4] + next_word(ring, i + 4));
    one_round(v->d, v->e, &v->g, v->h, v->a, v->b, &v->c, b_xor_c, k[5] + next_word(ring, i + 5));
    one_round(v->c, v->d, &v->f, v->g, v->h, v->a, &v->b, b_xor_c, k[6] + next_word(ring, i + 6));
    one_round(v->b, v->c, &v->e, v->f, v->g, v->h, &v->a, b_xor_c, k[7] + next_word(ring, i + 7));
}

// The sixteen words of the block at p into the ring, written out so that every index into the
// ring is a constant, here and in every round.
static inline void load_block(uint64_t ring[16], const uint8_t *p) {
    ring[0] = load_word(p);
    ring[1] = load_word(p + 8);
    ring[2] = load_word(p + 16);
    ring[3] = load_word(p + 24);
    ring[4] = load_word(p + 32);
    ring[5] = load_word(p + 40);
    ring[6] = load_word(p + 48);
    ring[7] = load_word(p + 56);
    ring[8] = load_word(p + 64);
    ring[9] = load_word(p + 72);
    ring[10] = load_word(p + 80);
    ring[11] = load_word(p + 88);
    ring[12] = load_word(p + 96);
    ring[13] = load_word(p + 104);
    ring[14] = load_word(p + 112);
    ring[15] = load_word(p + 120);
}

// FIPS 180-4 §6.4.2 step 4 for one block and step 2 for the next: each working variable takes
// the state word added to it, and the state word takes that sum.
static inline void end_block(uint64_t state[8], working_variables *v) {
    v->a += kept(&state[0]);
    v->b += kept(&state[1]);
    v->c += kept(&state[2]);
    v->d += kept(&state[3]);
    v->e += kept(&state[4]);
    v->f += kept(&state[5]);
    v->g += kept(&state[6]);
    v->h += kept(&state[7]);
    state[0] = v->a;
    state[1] = v->b;
    state[2] = v->c;
    state[3] = v->d;
    state[4] = v->e;
    state[5] = v->f;
    state[6] = v->g;
    state[7] = v->h;
    v->b_xor_c = v->b ^ v->c;
}

void sha512_compress_blocks(uint64_t state[8], const uint8_t *p, size_t blocks) {
    uint64_t ring[16];
    working_variables v;
    v.a = state[0];
    v.b = state[1];
    v.c = state[2];
    v.d = state[3];
    v.e = state[4];
    v.f = state[5];
    v.g = state[6];
    v.h = state[7];
    v.b_xor_c = v.b ^ v.c;
    for (; blocks > 0; blocks--) {
        load_block(ring, p);
        eight_rounds(&v, &sha512_round_constants[0], &ring[0]);
        eight_rounds(&v, &sha512_round_constants[8], &ring[8]);
        for (size_t first = 16; first < 80; first += 16) {
            eight_rounds_advancing(&v, &sha512_round_constants[first], ring, 0);
            eight_rounds_advancing(&v, &sha512_round_constants[first + 8], ring, 8);
        }
        end_block(state, &v);
        p += SHA512_BLOCK;
    }
}

#endif // CH_CPU_RUNTIME
