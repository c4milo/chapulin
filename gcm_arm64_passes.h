// The passes of gcm_arm64.c's seal and open in inline assembly: 8 blocks
// of counter mode and GHASH over 8 blocks of ciphertext a pass. Included
// by gcm_arm64.c only, after its target pragma, so every function here
// carries "+aes", and "+sha3" where gcm_arm64_eor3.c compiles gcm_arm64.c
// with GCM_ARM64_EOR3. gcm_arm64.c states why the passes are assembly.
//
// A pass, for each key size:
//
//   1. The pass's 8 counter blocks are loaded from a buffer in memory. The
//      integer unit writes the counts of the pass two after it into a
//      third buffer, so no vector instruction builds a counter. A block in
//      a buffer holds its count alone, in bytes 12 to 15, and zeros: the
//      first round adds the IV in bytes 0 to 11 with round key 0, which
//      first_key holds that sum of, so no buffer holds a byte of the IV.
//   2. The AES rounds run on the 8 blocks. After every second round of
//      AES-128, or every third round of AES-256, the products of 2 GHASH
//      blocks follow, so the core always has both kinds of work.
//   3. The last round, the exclusive-or with the last round key and the
//      input, and the store of the 8 output blocks.
//   4. A reduction of the sums into the accumulator. Paired passes take
//      H^16 to H^9 for the first pass's blocks and H^8 to H^1 for the
//      second's, and reduce once. A pass with no partner reduces alone.
//
// The seal hashes the ciphertext the pass before stored, and the open
// hashes its own pass's input, so one sequence with a pointer to the 8
// blocks serves both. In the open, every load of a pass's ciphertext
// comes before the first store of its plaintext, so out == in and out
// below in work.
//
// GHASH runs ghash_vector.h's arithmetic in the same element layout:
// Karatsuba's three products for each block, by the powers of H that
// ghash_compute_powers wrote, and ghash_reduce's two folds by the
// constant 0xc2. The middle products of 2 blocks share a register: TRN1
// and TRN2 put the two blocks' low and high words side by side, one
// exclusive-or adds them, and PMULL and PMULL2 multiply each lane by the
// two powers' halves added, which packed holds side by side.
//
// Registers. Each asm statement names the values it shares with the
// statements after it as operands, and the compiler keeps them in vector
// registers it picks: the 8 AES states, the accumulator and the three
// sums, and the pointers to the round keys, the blocks to hash and the
// powers. Every other register a statement writes is fixed and in its
// clobber list:
//
//   v16, v17 round keys, in turn       v26, v27 the 2 powers of H
//   v18      the last round key        v28      the pair's 2 powers' halves
//   v19      an input block, and the            added, then the reduction's
//            pair's middle words                constant
//   v24, v25 the 2 GHASH blocks        v29-v31  products and temporaries
//   x9, x11-x14 the pass_args members, below, and x15 a count
//
// Timing. No instruction here branches, and every address is a pointer
// the caller passed plus a constant. The C branches read the round count
// and the pass count.
#ifndef CH_GCM_ARM64_PASSES_H
#define CH_GCM_ARM64_PASSES_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ghash_vector.h"

#define GCM_ARM64_PASS_BLOCKS GHASH_PASS_BLOCKS
#define GCM_ARM64_PASS_BYTES ((size_t)GCM_ARM64_PASS_BLOCKS * AES_BLOCK)
_Static_assert(GCM_ARM64_PASS_BLOCKS == 8, "the asm below writes out 8 blocks a pass");

// The counter buffers. A pass writes the counts of the pass two after it,
// so the 4-byte stores have left the core before a 16-byte load of the
// same block reads them: a load that overlaps a store still in flight and
// is wider than it waits for it. With the pass after it as the target, a
// 16 KiB record's passes took 3.92 µs on a Neoverse N2, and 3.67 µs with
// the pass two after it.
#define GCM_ARM64_BUFFERS 3

// The fewest passes a call reduces two at a time. The pairs take H^9 to
// H^16 as well, which 8 more multiplies compute, and each pair saves one
// reduction of about 10 vector instructions. On a Neoverse N2 a 1 KiB
// record's 8 passes took about 30 ns longer in pairs, and a 16 KiB
// record's 128 about 80 ns less.
#define GCM_ARM64_PAIRED_PASSES 32

// What the passes keep in memory beside the GHASH state: H^9 to H^16
// times x^-1 as ghash_state keeps H to H^8, the pairs' powers' halves
// added side by side for both sets, and round key 0 exclusive-ored with
// the IV, which a caller wipes, and the counter buffers, which hold block
// counts alone and so no secret.
typedef struct {
    ghash_vector packed[GCM_ARM64_PASS_BLOCKS / 2];
    uint8_t first_key[AES_BLOCK];
    ghash_power high[GCM_ARM64_PASS_BLOCKS]; // high[i] holds H^(9 + i) * x^-1
    ghash_vector packed_high[GCM_ARM64_PASS_BLOCKS / 2];
    uint8_t counters[GCM_ARM64_BUFFERS][GCM_ARM64_PASS_BYTES];
} gcm_arm64_passes;

// How many bytes of a gcm_arm64_passes hold values computed from the key
// and the IV: up to high when the passes run alone, up to counters when
// they run in pairs.
static inline size_t passes_secret_len(int paired) {
    return paired ? offsetof(gcm_arm64_passes, counters) : offsetof(gcm_arm64_passes, high);
}

// What the asm reads from memory once a pass, in one object that one
// operand points at: gcc refuses an asm statement with more than 30
// operands, and counts each value a statement both reads and writes
// twice. A statement loads the members it needs into fixed registers
// first. The offsets below are the asm's.
typedef struct {
    uint8_t *cur;             // offset 0, into x11: this pass's counter blocks
    uint8_t *nxt;             // offset 8, into x12: the counter blocks two passes on
    const uint8_t *in;        // offset 16, into x13
    uint8_t *out;             // offset 24, into x14
    uint64_t next;            // offset 32, into x9: the first count two passes on
    uint64_t constant;        // offset 40, into d28: ghash_reduce's 0xc200000000000000
    const uint8_t *first_key; // offset 48, into x13 in the first statement
} pass_args;
_Static_assert(offsetof(pass_args, cur) == 0 && offsetof(pass_args, nxt) == 8 &&
                   offsetof(pass_args, in) == 16 && offsetof(pass_args, out) == 24 &&
                   offsetof(pass_args, next) == 32 && offsetof(pass_args, constant) == 40 &&
                   offsetof(pass_args, first_key) == 48,
               "the asm reads pass_args at these offsets");
_Static_assert(sizeof(ghash_power) == 32, "the asm reads power i at 32 * i");

// ---- The asm text. Each macro is a string of instructions. ----

// The operands every statement shares: the values in vector registers, the
// pass_args, the four pointers, and the fixed registers it writes.
#define SHARED                                                                                     \
    : [s0] "+w"(s0), [s1] "+w"(s1), [s2] "+w"(s2), [s3] "+w"(s3), [s4] "+w"(s4), [s5] "+w"(s5),   \
      [s6] "+w"(s6), [s7] "+w"(s7), [acc] "+w"(acc), [lo] "+w"(lo), [hi] "+w"(hi),                \
      [mid] "+w"(mid)                                                                             \
    : [a] "r"(args), [k] "r"(keys), [h] "r"(hash), [p] "r"(powers), [q] "r"(packed)     \
    : "memory", "x9", "x11", "x12", "x13", "x14", "x15", "v16", "v17",                            \
      "v18", "v19", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
#define STEP(text) __asm__ volatile(text SHARED)

// The values SHARED names, declared in each function that runs STEP:
// hash points at the blocks a pass hashes, powers and packed at its powers.
#define PASS_VALUES                                                                                \
    uint8x16_t s0 = vdupq_n_u8(0);                                                                 \
    uint8x16_t s1 = s0;                                                                            \
    uint8x16_t s2 = s0;                                                                            \
    uint8x16_t s3 = s0;                                                                            \
    uint8x16_t s4 = s0;                                                                            \
    uint8x16_t s5 = s0;                                                                            \
    uint8x16_t s6 = s0;                                                                            \
    uint8x16_t s7 = s0;                                                                            \
    ghash_vector zero = vdupq_n_u64(0);                                                            \
    ghash_vector lo = zero;                                                                        \
    ghash_vector hi = zero;                                                                        \
    ghash_vector mid = zero;                                                                       \
    const uint8_t *const keys = at->round_keys;                                                    \
    const uint8_t *hash = args->in;                                                                \
    const ghash_power *powers = at->powers;                                                        \
    const ghash_vector *packed = at->packed

// The pass_args members a macro below reads, which its statement loads first.
#define WITH_COUNTERS "ldp x11, x12, [%[a]]\n ldr x9, [%[a], 32]\n"
#define WITH_BLOCKS "ldp x13, x14, [%[a], 16]\n"

// D = A ^ B ^ C on 16 bytes, D never C: one EOR3 in gcm_arm64_eor3.c's
// copy, whose session's ch_cfg.cpu states FEAT_SHA3, and two EORs here.
#ifdef GCM_ARM64_EOR3
#define XOR3(D, A, B, C) "eor3 " D ".16b, " A ".16b, " B ".16b, " C ".16b\n"
#else
#define XOR3(D, A, B, C)                                                                           \
    "eor " D ".16b, " A ".16b, " B ".16b\n eor " D ".16b, " D ".16b, " C ".16b\n"
#endif

// One round of FIPS 197 §5.1 without the last on state S: AESE with the
// round key in register K, then MixColumns. AESE and AESMC on one register
// in turn let the core run them as one instruction.
#define AES_STATE(S, K) "aese %[" S "].16b, v" K ".16b\n aesmc %[" S "].16b, %[" S "].16b\n"
// Round R on the 8 states, with round key R loaded into register K first
// from the round keys at k.
#define ROUND_8(K)                                                                                 \
    AES_STATE("s0", K)                                                                             \
    AES_STATE("s1", K)                                                                             \
    AES_STATE("s2", K)                                                                             \
    AES_STATE("s3", K) AES_STATE("s4", K) AES_STATE("s5", K) AES_STATE("s6", K) AES_STATE("s7", K)
#define ROUND(R, K) "ldr q" K ", [%[k], #(16 * " #R ")]\n" ROUND_8(K)
// Round 0, whose AddRoundKey takes first_key, so it adds the IV as well.
#define ROUND_0 "ldr x13, [%[a], 48]\n ldr q16, [x13]\n" ROUND_8("16")

// Step 1: the 8 counter blocks of this pass, and the counts of the pass
// two after it, next to next + 7, into its buffer. Bytes 0 to 11 of each
// block stay zero from passes_counters, so a pass writes the count alone,
// big-endian in bytes 12 to 15. REV reverses the four bytes of the count,
// and STR writes them low byte first, so on a little-endian core
// (cpu_cfg.h) the most significant byte of the count lands at byte 12.
#define NEXT_COUNT(B) "add w15, w9, " #B "\n rev w15, w15\n str w15, [x12, #(16 * " #B " + 12)]\n"
#define COUNTERS                                                                                   \
    "ldp %q[s0], %q[s1], [x11]\n ldp %q[s2], %q[s3], [x11, 32]\n"                                  \
    "ldp %q[s4], %q[s5], [x11, 64]\n ldp %q[s6], %q[s7], [x11, 96]\n"                              \
    "rev w15, w9\n str w15, [x12, 12]\n" NEXT_COUNT(1) NEXT_COUNT(2) NEXT_COUNT(3) NEXT_COUNT(4)   \
        NEXT_COUNT(5) NEXT_COUNT(6) NEXT_COUNT(7)

// Blocks J and K of the 8 at h, as elements: ghash_load_block's byte
// reversal in each half. Block J takes power index 7 - J at p, H^(8 - J)
// in ghash_state's powers and H^(16 - J) in high, and so does K; packed[P]
// at q holds both powers' halves added.
#define PAIR_LOAD(J, K, P)                                                                         \
    "ldr q24, [%[h], #(16 * " #J ")]\n ldr q25, [%[h], #(16 * " #K ")]\n"                          \
    "rev64 v24.16b, v24.16b\n rev64 v25.16b, v25.16b\n"                                            \
    "ldr q26, [%[p], #(32 * (7 - " #J "))]\n ldr q27, [%[p], #(32 * (7 - " #K "))]\n"              \
    "ldr q28, [%[q], #(16 * " #P ")]\n"

// The pair's products: low = lane 1 times lane 1 (PMULL2), high = lane 0
// times lane 0 (PMULL), as ghash_start_sums computes them, and the middle
// products of both blocks from one register. SET starts a sum with the
// first pair's two products, and ADD adds a later pair's to it.
#define PAIR_PRODUCTS(SUM_LOW, SUM_HIGH, SUM_MIDDLE)                                               \
    "pmull2 v29.1q, v24.2d, v26.2d\n pmull2 v30.1q, v25.2d, v27.2d\n" SUM_LOW                      \
    "pmull v29.1q, v24.1d, v26.1d\n pmull v30.1q, v25.1d, v27.1d\n" SUM_HIGH                       \
    "trn1 v19.2d, v24.2d, v25.2d\n trn2 v31.2d, v24.2d, v25.2d\n"                                  \
    "eor v19.16b, v19.16b, v31.16b\n"                                                              \
    "pmull v29.1q, v19.1d, v28.1d\n pmull2 v30.1q, v19.2d, v28.2d\n" SUM_MIDDLE
#define SET(S) "eor %[" S "].16b, v29.16b, v30.16b\n"
#define ADD(S) XOR3("%[" S "]", "%[" S "]", "v29", "v30")
#define PAIR_FIRST(J, K, P) PAIR_LOAD(J, K, P) PAIR_PRODUCTS(SET("lo"), SET("hi"), SET("mid"))
#define PAIR(J, K, P) PAIR_LOAD(J, K, P) PAIR_PRODUCTS(ADD("lo"), ADD("hi"), ADD("mid"))
// The last pair of 8 blocks that start a GHASH run holds block 0, which
// the accumulator is added to first, as ghash_hash_pass adds it.
#define PAIR_LAST(J, P)                                                                            \
    PAIR_LOAD(J, 0, P)                                                                             \
    "eor v25.16b, v25.16b, %[acc].16b\n" PAIR_PRODUCTS(ADD("lo"), ADD("hi"), ADD("mid"))

// Step 3, for state S and block B: the last round, which drops
// MixColumns, the exclusive-or with the last round key in v18 and with
// the input block, and the store.
#define LAST_BLOCK(S, B)                                                                           \
    "ldr q19, [x13, #(16 * " #B ")]\n aese %[" S                                                   \
    "].16b, v16.16b\n" XOR3("%[" S "]", "%[" S "]", "v18", "v19") "str %q[" S                      \
                                                                  "], [x14, #(16 * " #B ")]\n"
#define LAST(R)                                                                                    \
    "ldr q16, [%[k], #(16 * (" #R " - 1))]\n ldr q18, [%[k], #(16 * " #R                           \
    ")]\n" LAST_BLOCK("s0", 0) LAST_BLOCK("s1", 1) LAST_BLOCK("s2", 2) LAST_BLOCK("s3", 3)         \
        LAST_BLOCK("s4", 4) LAST_BLOCK("s5", 5) LAST_BLOCK("s6", 6) LAST_BLOCK("s7", 7)

// Step 4: ghash_reduce. The middle term takes the low and high sums. The
// first fold adds low's lane 0 times the constant to low swapped and to
// the middle's lane 0. The second fold does the same to the first. The
// high sum, the middle's lane 1 and the second fold, swapped, are the new
// accumulator.
#define REDUCE                                                                                     \
    XOR3("%[mid]", "%[mid]", "%[lo]", "%[hi]")                                                     \
    "ldr d28, [%[a], 40]\n pmull v29.1q, %[lo].1d, v28.1d\n"                                       \
    "ext v30.16b, %[lo].16b, %[lo].16b, 8\n mov d27, %[mid].d[1]\n fmov d31, %d[mid]\n" XOR3(      \
        "v30", "v30", "v31",                                                                       \
        "v29") "eor %[hi].16b, %[hi].16b, v27.16b\n"                                               \
               "pmull v29.1q, v30.1d, v28.1d\n ext v30.16b, v30.16b, v30.16b, 8\n" XOR3(           \
                   "%[acc]", "%[hi]", "v30", "v29") "ext %[acc].16b, %[acc].16b, %[acc].16b, 8\n"

// The GHASH steps of a pass, which the AES rounds below run between. A
// pass that reduces 8 blocks alone (SINGLE), the first of two passes that
// reduce 16 blocks once (FIRST_OF_TWO), with the powers from H^9 up and
// no reduction, and the second of them (SECOND_OF_TWO), whose sums go on
// from the first's and whose block 0 takes no accumulator. Each names the
// powers its pairs take, and its pairs in order.
#define SINGLE_POWERS powers = low_powers, packed = low_packed
#define SINGLE_1 PAIR_FIRST(1, 2, 0)
#define SINGLE_2 PAIR(3, 4, 1)
#define SINGLE_3 PAIR(5, 6, 2)
#define SINGLE_4 PAIR_LAST(7, 3)
#define SINGLE_END REDUCE
#define FIRST_OF_TWO_POWERS powers = high_powers, packed = high_packed
#define FIRST_OF_TWO_1 PAIR_FIRST(1, 2, 0)
#define FIRST_OF_TWO_2 PAIR(3, 4, 1)
#define FIRST_OF_TWO_3 PAIR(5, 6, 2)
#define FIRST_OF_TWO_4 PAIR_LAST(7, 3)
#define FIRST_OF_TWO_END ""
#define SECOND_OF_TWO_POWERS powers = low_powers, packed = low_packed
#define SECOND_OF_TWO_1 PAIR(1, 2, 0)
#define SECOND_OF_TWO_2 PAIR(3, 4, 1)
#define SECOND_OF_TWO_3 PAIR(5, 6, 2)
#define SECOND_OF_TWO_4 PAIR(7, 0, 3)
#define SECOND_OF_TWO_END REDUCE

// A pass of AES-128 with the GHASH steps of KIND: 9 rounds with
// MixColumns, a GHASH pair after each second one, and the last round, in 7
// statements. No one string may pass the 4095 characters ISO C requires a
// compiler to take, so a pass is several statements, and the shared
// operands carry the values between them.
#define PASS_128(KIND)                                                                             \
    KIND##_POWERS;                                                                                 \
    STEP(WITH_COUNTERS COUNTERS ROUND_0 ROUND(1, "17"));                                           \
    STEP(KIND##_1 ROUND(2, "16") ROUND(3, "17"));                                                  \
    STEP(KIND##_2 ROUND(4, "16") ROUND(5, "17"));                                                  \
    STEP(KIND##_3 ROUND(6, "16") ROUND(7, "17"));                                                  \
    STEP(KIND##_4 ROUND(8, "16"));                                                                 \
    STEP(WITH_BLOCKS LAST(10) KIND##_END)

// A pass of AES-256 with the GHASH steps of KIND: 13 rounds with
// MixColumns, a GHASH pair after each third one, and the last round, in 8
// statements.
#define PASS_256(KIND)                                                                             \
    KIND##_POWERS;                                                                                 \
    STEP(WITH_COUNTERS COUNTERS ROUND_0 ROUND(1, "17"));                                           \
    STEP(ROUND(2, "16") KIND##_1 ROUND(3, "17"));                                                  \
    STEP(ROUND(4, "16") ROUND(5, "17") KIND##_2);                                                  \
    STEP(ROUND(6, "16") ROUND(7, "17") ROUND(8, "16"));                                            \
    STEP(KIND##_3 ROUND(9, "17") ROUND(10, "16"));                                                 \
    STEP(ROUND(11, "17") KIND##_4);                                                                \
    STEP(ROUND(12, "16"));                                                                         \
    STEP(WITH_BLOCKS LAST(14) KIND##_END)

// The seal's first pass: counter mode alone, with no GHASH step.
#define COUNTER_PASS_128                                                                           \
    STEP(WITH_COUNTERS COUNTERS ROUND_0 ROUND(1, "17") ROUND(2, "16"));                            \
    STEP(ROUND(3, "17") ROUND(4, "16") ROUND(5, "17") ROUND(6, "16"));                             \
    STEP(ROUND(7, "17") ROUND(8, "16"));                                                           \
    STEP(WITH_BLOCKS LAST(10))
#define COUNTER_PASS_256                                                                           \
    STEP(WITH_COUNTERS COUNTERS ROUND_0 ROUND(1, "17") ROUND(2, "16"));                            \
    STEP(ROUND(3, "17") ROUND(4, "16") ROUND(5, "17") ROUND(6, "16"));                             \
    STEP(ROUND(7, "17") ROUND(8, "16") ROUND(9, "17") ROUND(10, "16"));                            \
    STEP(ROUND(11, "17") ROUND(12, "16"));                                                         \
    STEP(WITH_BLOCKS LAST(14))

// The seal's last GHASH, the GHASH steps of KIND with no AES step.
#define HASH_PASS(KIND)                                                                            \
    KIND##_POWERS;                                                                                 \
    STEP(KIND##_1 KIND##_2);                                                                       \
    STEP(KIND##_3 KIND##_4 KIND##_END)

// The counter's count block b of pass p takes: first counts from 1, as
// SP 800-38D's inc32 of the first counter block J0, whose count is 1.
static inline uint32_t passes_count(uint32_t first, size_t p, size_t b) {
    return first + (uint32_t)(p * GCM_ARM64_PASS_BLOCKS + b);
}

// ps's first_key: round key 0 with the twelve bytes of iv exclusive-ored
// into bytes 0 to 11. Its counter buffers 0 and 1: the counter blocks of
// passes 0 and 1, whose counts begin at first, as NEXT_COUNT writes them.
// Its buffer 2: zeros, which the asm writes counts into.
static inline void passes_counters(gcm_arm64_passes *ps, const uint8_t *round_keys,
                                   const uint8_t iv[AES_IV], uint32_t first) {
    uint64_t iv_low;
    uint32_t iv_high;
    memcpy(&iv_low, iv, sizeof iv_low);
    memcpy(&iv_high, &iv[sizeof iv_low], sizeof iv_high);
    uint8x16_t iv_block =
        vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(iv_low), vcreate_u64(iv_high)));
    vst1q_u8(ps->first_key, veorq_u8(vld1q_u8(round_keys), iv_block));
    memset(ps->counters[2], 0, sizeof ps->counters[2]);
    for (size_t p = 0; p < 2; p++) {
        for (size_t b = 0; b < GCM_ARM64_PASS_BLOCKS; b++) {
            uint64_t words[2] = {0, (uint64_t)__builtin_bswap32(passes_count(first, p, b)) << 32};
            memcpy(&ps->counters[p][b * AES_BLOCK], words, sizeof words);
        }
    }
}

// packed[k]: the halves added of the powers in powers that pair k's two
// blocks take, in lanes 0 and 1: blocks 2k + 1 and 2k + 2, and block 0 in
// the last pair's lane 1, where block j takes powers[7 - j].
static inline void passes_pack_set(ghash_vector packed[GCM_ARM64_PASS_BLOCKS / 2],
                                   const ghash_power powers[GCM_ARM64_PASS_BLOCKS]) {
    for (size_t k = 0; k < GCM_ARM64_PASS_BLOCKS / 2; k++) {
        size_t j = 2 * k + 1;
        size_t other = (j + 1) % GCM_ARM64_PASS_BLOCKS;
        packed[k] = vtrn1q_u64(powers[7 - j].halves_added, powers[7 - other].halves_added);
    }
}

// Where the passes stand between two passes, beside the pass_args: the
// counter buffer after the one the next pass reads, where the pass just
// run wrote its output, the first count two passes on, and the asm's
// pointer operands. The asm reads args through a pointer and may write
// any memory, so the compilers reload args after each statement and keep
// these in registers.
typedef struct {
    uint8_t *following;
    const uint8_t *written;
    uint32_t next;
    const uint8_t *round_keys;
    const ghash_power *powers;
    const ghash_vector *packed;
    const ghash_power *high;
    const ghash_vector *packed_high;
} pass_cursor;

// args and at for pass 0 over in and out, with ps as passes_counters wrote
// it and first the count of pass 0's block 0.
static inline void passes_begin(pass_args *args, pass_cursor *at, gcm_arm64_passes *ps,
                                const ghash_state *g, const uint8_t *round_keys, uint32_t first,
                                const uint8_t *in, uint8_t *out) {
    at->round_keys = round_keys;
    args->first_key = ps->first_key;
    at->powers = g->powers;
    at->packed = ps->packed;
    at->high = ps->high;
    at->packed_high = ps->packed_high;
    args->constant = GHASH_REDUCTION_WORD;
    args->cur = ps->counters[0];
    at->following = ps->counters[1];
    args->nxt = ps->counters[2];
    args->in = in;
    args->out = out;
    at->written = NULL;
    at->next = passes_count(first, 2, 0);
    args->next = at->next;
}

// One pass on: the counter buffers turn, the pointers move on by a pass,
// and written is where the pass just run wrote its output.
static inline void pass_advance(pass_args *args, pass_cursor *at) {
    uint8_t *read = args->cur;
    args->cur = at->following;
    at->following = args->nxt;
    args->nxt = read;
    at->written = args->out;
    args->in += GCM_ARM64_PASS_BYTES;
    args->out += GCM_ARM64_PASS_BYTES;
    at->next += GCM_ARM64_PASS_BLOCKS;
    args->next = at->next;
}

// The seal's first pass: counter mode alone, which needs no power of H, so
// the core can run it and the caller's powers at once.
static inline void passes_counter_pass(pass_args *args, pass_cursor *at, size_t rounds) {
    PASS_VALUES;
    ghash_vector acc = zero;
#ifdef CH_AES_256
    if (rounds == AES_256_ROUNDS) {
        COUNTER_PASS_256;
        pass_advance(args, at);
        return;
    }
#else
    (void)rounds;
#endif
    COUNTER_PASS_128;
    pass_advance(args, at);
}

// count passes on the asm from where args and at stand, from g's
// accumulator. When seal is set, each pass hashes the 8 blocks the pass
// before wrote, and the last pass's 8 blocks are hashed after the loop;
// when it is not, each pass hashes its own input. When paired is set, two
// passes in turn reduce their 16 blocks once, and a pass with no partner
// reduces its 8 alone: the open's last pass when count is odd, and the
// seal's last hash when count is even. seal, paired and rounds come from
// the length and the suite, so the branches read no secret. Each loop runs
// one key size's passes with no branch between two passes: where a branch
// joined two sequences, gcc 13 moved the shared values between registers.
#define PASSES_LOOP(PASS)                                                                          \
    do {                                                                                           \
        size_t p = 0;                                                                              \
        for (; !paired && p < count; p++) {                                                        \
            hash = seal ? at->written : args->in;                                                  \
            PASS(SINGLE);                                                                          \
            pass_advance(args, at);                                                                \
        }                                                                                          \
        for (; p + 2 <= count; p += 2) {                                                           \
            hash = seal ? at->written : args->in;                                                  \
            PASS(FIRST_OF_TWO);                                                                    \
            pass_advance(args, at);                                                                \
            hash = seal ? at->written : args->in;                                                  \
            PASS(SECOND_OF_TWO);                                                                   \
            pass_advance(args, at);                                                                \
        }                                                                                          \
        if (p < count && seal) {                                                                   \
            hash = at->written;                                                                    \
            PASS(FIRST_OF_TWO);                                                                    \
            pass_advance(args, at);                                                                \
            hash = at->written;                                                                    \
            HASH_PASS(SECOND_OF_TWO);                                                              \
        } else if (p < count) {                                                                    \
            hash = args->in;                                                                       \
            PASS(SINGLE);                                                                          \
            pass_advance(args, at);                                                                \
        } else if (seal) {                                                                         \
            hash = at->written;                                                                    \
            HASH_PASS(SINGLE);                                                                     \
        }                                                                                          \
    } while (0)

static inline void passes_run(ghash_state *g, pass_args *args, pass_cursor *at, size_t rounds,
                              int seal, int paired, size_t count) {
    PASS_VALUES;
    ghash_vector acc = g->acc;
    const ghash_power *const low_powers = at->powers;
    const ghash_power *const high_powers = at->high;
    const ghash_vector *const low_packed = at->packed;
    const ghash_vector *const high_packed = at->packed_high;
#ifdef CH_AES_256
    if (rounds == AES_256_ROUNDS) {
        PASSES_LOOP(PASS_256);
        g->acc = acc;
        return;
    }
#else
    (void)rounds;
#endif
    PASSES_LOOP(PASS_128);
    g->acc = acc;
}

#endif
