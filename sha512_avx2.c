// The SHA-512 compression function (FIPS 180-4 §6.4.2) over whole blocks for an x86-64 host
// object's sessions with CH_CPU_AVX2 (sha512_avx2.h, docs/decisions.md 128). The message
// schedule runs in 256-bit registers, four words of one block to a register, and the rounds run
// in general registers, as in sha512_compress_blocks.c. On any other target this file holds
// nothing: sha512_avx2.h is here so that it is a translation unit still.
//
// sha512_compress.c stays the reference. This file computes the same state and differs from
// sha512_compress_blocks.c, the plain C a session without the bit runs, in where the schedule
// is computed:
//
//   four registers hold the sixteen newest schedule words, the earliest in the lowest lane;
//   one step computes the four words sixteen after a register's and writes them over it;
//   each step adds the four round constants of its words and stores the four sums to an array
//   on the stack, and a round reads its sum from that array;
//   the rounds are written out eight to a pass, and a quarter of a step follows each of them:
//   the step that replaces the register whose sums the four rounds around it read.
//
// A step's instructions are on vector registers and a round's on general registers. With each
// step whole after its four rounds, as this file first had it, SHA-384 over 16 KiB took 1 to 8
// percent longer under gcc on each of four CPU models, and longer under clang on three of them
// (docs/decisions.md 128). The order is the source's, and a compiler may write another. clang
// writes the instructions in the source's order. gcc's second scheduling pass, which runs after
// gcc has picked registers, moves each step's vector instructions in among those of one or two
// rounds and leaves the rounds after them with none. So the Makefile compiles this file with
// -fno-schedule-insns2, which turns that pass off, wherever gcc compiles it for x86-64, and
// gives the flag to no other file (SHA512_AVX2_GCC_CFLAGS there). A gcc build of this file by
// any other means computes the same state in that slower order unless it passes the flag. make
// lint-schedule-order reads the order each compiler wrote (INV-51).
//
// The object compiles this file with no instruction flag, so the rest of the object runs on any
// x86-64 CPU. The pragma below puts the target attribute that turns AVX2 on onto each function
// in this file and on no function outside it, as chacha20_avx2.c does. The attribute names
// AVX2 alone: no function here may run a BMI1 or BMI2 instruction, which CH_CPU_AVX2 does not
// state. Nothing here probes a CPU: the caller does, and states what it found in ch_cfg.cpu.
//
// SHA-384 is the hash of TLS_AES_256_GCM_SHA384's key schedule, so this file reads HMAC keys
// and traffic secrets. Its operations are adds, rotates, shifts, bitwise logic and byte
// shuffles by constant masks, it reads the round constants at indices the round number fixes,
// and it branches on the block count alone. CH_CPU_AVX2 states that the instructions exist and
// no timing, as it does for chacha20_avx2.c, which runs the same kinds of instruction on a key.
//
// What a call computes from the message it leaves in its own frame: the last sixteen sums, and
// whichever registers the compiler wrote to stack slots of its own. So the caller wipes the
// stack below itself after the call (sha512.c). The vector registers hold schedule words when
// the last block ends, and the function writes zero to all sixteen before it returns.
//
// CBMC cannot read an intrinsic, so no proof compiles this file. bin/sha2_equiv_test holds it
// to sha512.c's second arm over sha512_compress.c on a CPU with AVX2, searches the stack below
// each kind of call and reads the sixteen registers after one (docs/verification.md, "SHA-512 on
// AVX2").
#include "sha512_avx2.h"

#if defined(CH_CPU_RUNTIME) && defined(__x86_64__)

#include <immintrin.h>

#include "sha512_round_constants.h"

// Every function from here to the pop at the end of this file carries the target attribute that
// turns AVX2 on: clang applies it through one attribute push, and gcc's target pragma sets it
// for each function defined after it, until the pop.
#ifdef __clang__
#pragma clang attribute push(__attribute__((target("avx2"))), apply_to = function)
#else
#pragma GCC push_options
#pragma GCC target("avx2")
#endif

static inline __attribute__((always_inline)) uint64_t rotate_right(uint64_t x, unsigned r) {
    return (x >> r) | (x << (64 - r));
}

// FIPS 180-4 §4.1.3, equations 4.10 and 4.11, in the standard's three terms. On this kernel's
// rounds the three terms measured faster than sha512_compress_blocks.c's nested rotates
// (docs/decisions.md 128).
static inline __attribute__((always_inline)) uint64_t upper_sigma0(uint64_t x) {
    return rotate_right(x, 28) ^ rotate_right(x, 34) ^ rotate_right(x, 39);
}

static inline __attribute__((always_inline)) uint64_t upper_sigma1(uint64_t x) {
    return rotate_right(x, 14) ^ rotate_right(x, 18) ^ rotate_right(x, 41);
}

// Ch (equation 4.8) in three operations: where a bit of e is 1 the result is g ^ f ^ g, which
// is f, and where it is 0 the result is g.
static inline __attribute__((always_inline)) uint64_t choice(uint64_t e, uint64_t f, uint64_t g) {
    return g ^ (e & (f ^ g));
}

// Maj (equation 4.9): where a and b agree the result is b, and where they differ it is
// b ^ b ^ c, which is c, the vote of the third. The next round names this round's a and b as
// its b and c, so its b ^ c is this round's a ^ b, and a compiler computes one exclusive OR a
// round for the two.
static inline __attribute__((always_inline)) uint64_t majority(uint64_t a, uint64_t b, uint64_t c) {
    return b ^ ((a ^ b) & (b ^ c));
}

// The eight working variables of FIPS 180-4 §6.4.2 step 2.
typedef struct {
    uint64_t a;
    uint64_t b;
    uint64_t c;
    uint64_t d;
    uint64_t e;
    uint64_t f;
    uint64_t g;
    uint64_t h;
} working_variables;

// One round (FIPS 180-4 §6.4.2 step 3) that moves no value. Its arguments name the working
// variables by the role each has in this round. The round writes two variables: it adds T1 to
// the one at d, which is the next round's e, and writes T1 + T2 over the one at h, which is the
// next round's a. The other six keep their values and take the next role.
static inline __attribute__((always_inline)) void one_round(uint64_t a, uint64_t b, uint64_t c,
                                                            uint64_t *d, uint64_t e, uint64_t f,
                                                            uint64_t g, uint64_t *h,
                                                            uint64_t word_plus_constant) {
    uint64_t t1 = *h + word_plus_constant + choice(e, f, g) + upper_sigma1(e);
    *d += t1;
    *h = t1 + (upper_sigma0(a) + majority(a, b, c));
}

// Four 64-bit words in a 256-bit register, and two in a 128-bit one. Each operation below
// works on every lane at once and has no branch and no memory access that a lane's value
// decides.
typedef __m256i four_words;
typedef __m128i two_words;

// ROTR 8 of each lane. It moves whole bytes inside a lane, so one byte shuffle (VPSHUFB) does
// it: byte i of each 16 bytes of the result is byte order[i] of the same 16 bytes of x, and a
// lane's least significant byte comes first, so byte 1 moves to byte 0 and byte 0 to byte 7.
static inline __attribute__((always_inline)) four_words four_rotate_right_8(four_words x) {
    const four_words order = _mm256_setr_epi8(1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8,
                                              1, 2, 3, 4, 5, 6, 7, 0, 9, 10, 11, 12, 13, 14, 15, 8);
    return _mm256_shuffle_epi8(x, order);
}

// FIPS 180-4 §4.1.3, equation 4.12, on four lanes: ROTR 1 ^ ROTR 8 ^ SHR 7. AVX2 has no 64-bit
// rotation, so ROTR 1 is a shift right, a shift left and an exclusive OR.
static inline __attribute__((always_inline)) four_words four_lower_sigma0(four_words x) {
    four_words rotated_1 = _mm256_xor_si256(_mm256_srli_epi64(x, 1), _mm256_slli_epi64(x, 63));
    return _mm256_xor_si256(_mm256_xor_si256(rotated_1, four_rotate_right_8(x)),
                            _mm256_srli_epi64(x, 7));
}

// Equation 4.13 on two lanes: ROTR 19 ^ ROTR 61 ^ SHR 6.
static inline __attribute__((always_inline)) two_words two_lower_sigma1(two_words x) {
    two_words rotated_19 = _mm_xor_si128(_mm_srli_epi64(x, 19), _mm_slli_epi64(x, 45));
    two_words rotated_61 = _mm_xor_si128(_mm_srli_epi64(x, 61), _mm_slli_epi64(x, 3));
    return _mm_xor_si128(_mm_xor_si128(rotated_19, rotated_61), _mm_srli_epi64(x, 6));
}

// Four words of the block at p as the hash reads them, most significant byte first (FIPS 180-4
// §3.1). The 32 bytes are read as two halves of 16 that VINSERTI128 joins: gcc 13 sent one
// 32-byte load that a byte shuffle follows through a stack slot, where the message words then
// stayed. The shuffle reverses the bytes of each lane: byte i of each 16 bytes of the result is
// byte order[i] of the same 16 bytes.
static inline __attribute__((always_inline)) four_words load_four_words(const uint8_t *p) {
    const four_words order = _mm256_set_epi64x(0x08090a0b0c0d0e0fLL, 0x0001020304050607LL,
                                               0x08090a0b0c0d0e0fLL, 0x0001020304050607LL);
    two_words low = _mm_loadu_si128((const __m128i *)(const void *)p);
    two_words high = _mm_loadu_si128((const __m128i *)(const void *)(p + 16));
    four_words as_they_lie = _mm256_inserti128_si256(_mm256_castsi128_si256(low), high, 1);
    return _mm256_shuffle_epi8(as_they_lie, order);
}

// The upper three words of low and the lowest word of high: the four words that start one word
// after low's first, where high holds the four after low. VPBLENDD writes high's lowest word
// over low's, and VPERMQ then moves each word down one lane and that word to the top: 0x39
// names lanes 1, 2, 3 and 0 in that order.
static inline __attribute__((always_inline)) four_words one_word_on(four_words low,
                                                                    four_words high) {
    return _mm256_permute4x64_epi64(_mm256_blend_epi32(low, high, 0x03), 0x39);
}

// One schedule step computes W[t] to W[t + 3] (FIPS 180-4 §6.4.2 step 1) from the sixteen words
// before them and writes them over register j of w, which holds W[t - 16] to W[t - 13]. The
// registers are a ring of four: the one after j holds W[t - 12] to W[t - 9], the next W[t - 8]
// to W[t - 5], and the one before j W[t - 4] to W[t - 1]. W[t] and W[t + 1] take lower_sigma1
// of W[t - 2] and W[t - 1], and W[t + 2] and W[t + 3] take lower_sigma1 of W[t] and W[t + 1],
// so the lower half is computed first and each half in a 128-bit register.
//
// The step is written in four quarters, one after each of the four rounds that read the sums
// of register j, and this is what it holds between them.
typedef struct {
    // W[t - 16 + i] + W[t - 7 + i] + lower_sigma0(W[t - 15 + i]) for i from 0 to 3: each new
    // word less its lower_sigma1 term.
    four_words partial;
    // W[t] and W[t + 1].
    two_words lower;
} schedule_step;

// The first quarter of the step that replaces register j of w: the three terms of each new
// word that read none of the four.
static inline __attribute__((always_inline)) void
step_first_quarter(schedule_step *step, const four_words w[4], size_t j) {
    four_words fifteen_back = one_word_on(w[j], w[(j + 1) % 4]);
    four_words seven_back = one_word_on(w[(j + 2) % 4], w[(j + 3) % 4]);
    four_words sixteen_and_seven_back = _mm256_add_epi64(w[j], seven_back);
    step->partial = _mm256_add_epi64(sixteen_and_seven_back, four_lower_sigma0(fifteen_back));
}

// The second quarter: W[t] and W[t + 1]. W[t - 2] and W[t - 1] are the upper half of the
// register before j.
static inline __attribute__((always_inline)) void
step_second_quarter(schedule_step *step, const four_words w[4], size_t j) {
    two_words two_back = _mm256_extracti128_si256(w[(j + 3) % 4], 1);
    step->lower = _mm_add_epi64(_mm256_castsi256_si128(step->partial), two_lower_sigma1(two_back));
}

// The third quarter: W[t + 2] and W[t + 3], and the four new words over register j.
static inline __attribute__((always_inline)) void step_third_quarter(const schedule_step *step,
                                                                     four_words w[4], size_t j) {
    two_words upper =
        _mm_add_epi64(_mm256_extracti128_si256(step->partial, 1), two_lower_sigma1(step->lower));
    w[j] = _mm256_inserti128_si256(_mm256_castsi128_si256(step->lower), upper, 1);
}

// Writes the four words of register j of w, each plus its round constant, where the rounds
// read them: sums[4 * j] to sums[4 * j + 3]. constants holds the sixteen constants of the
// rounds that read the sums. Both arrays are aligned to 32 bytes, so the load and the store
// each lie inside one cache line. For the words a step computed, this is its fourth quarter.
static inline __attribute__((always_inline)) void
store_sums(uint64_t sums[16], const four_words w[4], size_t j, const uint64_t constants[16]) {
    four_words four_constants = _mm256_load_si256((const __m256i *)(const void *)&constants[4 * j]);
    _mm256_store_si256((__m256i *)(void *)&sums[4 * j], _mm256_add_epi64(w[j], four_constants));
}

// Eight rounds on sums[4 * from] to sums[4 * from + 7], and the two steps that replace the
// registers those sums came from, registers from and from + 1, a quarter after each round. from
// is 0 or 2. Each round names the working variables one place on from the round before it. A
// step's first three quarters store nothing, and its fourth stores the new sums over the four
// its rounds read, after the fourth of them has read its own. The reads are plain, so each is
// the memory operand of its round's add: every pass of the caller's loop reads what the pass
// before it stored, and no compiler can take such a sum from a register.
static inline __attribute__((always_inline)) void
eight_rounds_advancing(working_variables *v, four_words w[4], size_t from, uint64_t sums[16],
                       const uint64_t constants[16]) {
    const uint64_t *now = sums + 4 * from;
    schedule_step step;
    one_round(v->a, v->b, v->c, &v->d, v->e, v->f, v->g, &v->h, now[0]);
    step_first_quarter(&step, w, from);
    one_round(v->h, v->a, v->b, &v->c, v->d, v->e, v->f, &v->g, now[1]);
    step_second_quarter(&step, w, from);
    one_round(v->g, v->h, v->a, &v->b, v->c, v->d, v->e, &v->f, now[2]);
    step_third_quarter(&step, w, from);
    one_round(v->f, v->g, v->h, &v->a, v->b, v->c, v->d, &v->e, now[3]);
    store_sums(sums, w, from, constants);
    one_round(v->e, v->f, v->g, &v->h, v->a, v->b, v->c, &v->d, now[4]);
    step_first_quarter(&step, w, from + 1);
    one_round(v->d, v->e, v->f, &v->g, v->h, v->a, v->b, &v->c, now[5]);
    step_second_quarter(&step, w, from + 1);
    one_round(v->c, v->d, v->e, &v->f, v->g, v->h, v->a, &v->b, now[6]);
    step_third_quarter(&step, w, from + 1);
    one_round(v->b, v->c, v->d, &v->e, v->f, v->g, v->h, &v->a, now[7]);
    store_sums(sums, w, from + 1, constants);
}

// Eight of a block's last sixteen rounds, which no step follows. Each sum is read through a
// volatile pointer, so the read is a load from the array at the round. Read plainly, gcc 13
// took these sixteen sums out of the vector registers that had stored them, and kept those
// registers in stack slots of its own until the rounds ran.
static inline __attribute__((always_inline)) void eight_rounds(working_variables *v,
                                                               const volatile uint64_t *sums) {
    one_round(v->a, v->b, v->c, &v->d, v->e, v->f, v->g, &v->h, sums[0]);
    one_round(v->h, v->a, v->b, &v->c, v->d, v->e, v->f, &v->g, sums[1]);
    one_round(v->g, v->h, v->a, &v->b, v->c, v->d, v->e, &v->f, sums[2]);
    one_round(v->f, v->g, v->h, &v->a, v->b, v->c, v->d, &v->e, sums[3]);
    one_round(v->e, v->f, v->g, &v->h, v->a, v->b, v->c, &v->d, sums[4]);
    one_round(v->d, v->e, v->f, &v->g, v->h, v->a, v->b, &v->c, sums[5]);
    one_round(v->c, v->d, v->e, &v->f, v->g, v->h, v->a, &v->b, sums[6]);
    one_round(v->b, v->c, v->d, &v->e, v->f, v->g, v->h, &v->a, sums[7]);
}

// FIPS 180-4 §6.4.2 step 4: each word of the state plus its working variable. The state the
// block began with is read from the caller's array here, eighty rounds after step 2 read it,
// through a volatile pointer: a compiler that read it once kept the eight words in stack slots
// of its own for the eighty rounds.
static inline __attribute__((always_inline)) void end_block(uint64_t state[8],
                                                            const working_variables *v) {
    const volatile uint64_t *began_with = state;
    state[0] = began_with[0] + v->a;
    state[1] = began_with[1] + v->b;
    state[2] = began_with[2] + v->c;
    state[3] = began_with[3] + v->d;
    state[4] = began_with[4] + v->e;
    state[5] = began_with[5] + v->f;
    state[6] = began_with[6] + v->g;
    state[7] = began_with[7] + v->h;
}

// FIPS 180-4 §6.4.2 for the block at p: state in, state out, with the block's last sixteen
// schedule words plus their constants left in sums. The four loads are written out: in a loop
// that gcc 13 unrolled, it wrote each loaded register to a stack slot and read it back.
static inline __attribute__((always_inline)) void one_block(uint64_t state[8], const uint8_t *p,
                                                            uint64_t sums[16]) {
    four_words w[4] = {load_four_words(p), load_four_words(p + 32), load_four_words(p + 64),
                       load_four_words(p + 96)};
    store_sums(sums, w, 0, sha512_round_constants);
    store_sums(sums, w, 1, sha512_round_constants);
    store_sums(sums, w, 2, sha512_round_constants);
    store_sums(sums, w, 3, sha512_round_constants);
    working_variables v = {state[0], state[1], state[2], state[3],
                           state[4], state[5], state[6], state[7]};
    // Rounds 0 to 63, sixteen a pass. Each pass also computes the sixteen words after its own,
    // a quarter of a step after each round, and stores their sums, which the next pass reads.
    for (size_t next = 16; next < 80; next += 16) {
        eight_rounds_advancing(&v, w, 0, sums, &sha512_round_constants[next]);
        eight_rounds_advancing(&v, w, 2, sums, &sha512_round_constants[next]);
    }
    eight_rounds(&v, sums);
    eight_rounds(&v, sums + 8);
    end_block(state, &v);
}

// sums is declared with the alignment of a 256-bit register, so each store of four sums lies
// inside one cache line, and so that both compilers align this function's frame to 32 bytes.
// clang gives a stack slot it picks for a 256-bit register the alignment of the frame, and
// aligns a frame to 32 bytes only for a function that holds such an object or carries
// force_align_arg_pointer. Without the alignment the stores sit wherever the caller's stack
// pointer leaves them, in steps of 16 bytes, and one that lies across a cache line or a page
// boundary stalls (docs/decisions.md 124, INV-49). make lint-frame-align requires the aligned
// frame of this function under clang.
void sha512_avx2_compress_blocks(uint64_t state[8], const uint8_t *p, size_t blocks) {
    _Alignas(32) uint64_t sums[16];
    for (; blocks > 0; blocks--) {
        one_block(state, p, sums);
        p += SHA512_BLOCK;
    }
    // ymm0 to ymm15 hold schedule words of the last block, and VZEROALL writes zero to all
    // sixteen. It also leaves their upper halves clear, so the code this function returns to,
    // which is compiled without AVX, pays nothing for them.
    _mm256_zeroall();
}

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif

#endif // CH_CPU_RUNTIME && __x86_64__
