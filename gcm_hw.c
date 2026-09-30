// AES=hw and AES=runtime: AES-GCM's work over whole blocks on the AES
// instructions and the carry-less multiply. gcm_hw.h states the two
// contracts; this file implements them and nothing else.
//
// Counter mode runs GCM_HW_PASS_BLOCKS counter blocks through each round
// together. The rounds of one block do not depend on another block's, so
// the core runs the eight at once, and each round key is loaded once for
// them.
//
// The seal runs counter mode and GHASH over its ciphertext in one loop.
// Each pass runs the AES rounds of its eight counter blocks, writes their
// ciphertext, and then multiplies the eight ciphertext blocks the pass
// before wrote by the powers of H. Nothing in a pass waits on those
// products and nothing in them waits on the pass, so the core runs one
// pass's AES instructions and the carry-less multiplies of the pass
// before at the same time. Two other shapes measured slower
// (docs/performance.md): the products written between the rounds, which
// the compilers moved after them anyway, and the pass just written hashed
// in the same pass, whose products then wait on its rounds. GHASH's
// arithmetic is ghash_vector.h's, the same steps ghash_hw.c runs, and the
// last pass's ciphertext is hashed after the loop.
//
// Two instruction sets, as for aes_hw.c and ghash_vector.h, and the same
// macros pick between them: this file needs both the AES instructions and
// the carry-less multiply, which __ARM_FEATURE_AES names together on Arm
// and __AES__ and __PCLMUL__ name apart on x86-64. AES=runtime compiles
// this file with no instruction flag, and the pragma below puts the target
// attribute on each function in it, "+aes" on arm64 and "aes,pclmul" on
// x86-64. gcm.c calls this file only for a schedule the AES instructions
// run (aes_schedule.h).
//
// Timing. No line here branches on an operand or indexes memory with one.
// The branches read the round count and the block count, which are the
// suite's and the record's length. aes_hw.c states what the AES
// instructions can and cannot claim, and CH_NATIVE_AES is the build's
// statement for both instructions.
//
// Every value the seal computes from the key sits in one gcm_hw_state,
// wiped once when the call ends: the powers of H, the sums of a pass's
// products, the accumulator and a pass's keystream, which the output then
// writes over. Counter mode alone keeps its keystream in an array it wipes
// the same way.
//
// CBMC cannot read an intrinsic, so the proofs stay on gcm.c's one-block
// counter loop and portable GHASH, and test/aes_equiv_test.c and
// test/ghash_equiv_test.c hold this file to them byte for byte.
#include "gcm_hw.h"

#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#if defined(CH_AES_HW) || defined(CH_AES_RUNTIME)

#include <stddef.h>
#include <string.h>

#include "ct.h"
#include "ghash_vector.h"

// ghash_vector.h picks the architecture and refuses a build without the
// carry-less multiply; an AES=hw build for x86-64 needs AES-NI as well.
#if !defined(CH_AES_RUNTIME) && !defined(GHASH_VECTOR_ARM) && !defined(__AES__)
#error                                                                                             \
    "AES=hw needs the AES instructions: compile with -march=armv8-a+crypto or -maes -mpclmul, or build AES=soft"
#endif

// Under AES=runtime, every function from here to the pop at the end of
// this file carries the target attribute that turns both instructions on.
#ifdef CH_AES_RUNTIME
#ifdef __clang__
#ifdef GHASH_VECTOR_ARM
#pragma clang attribute push(__attribute__((target("+aes"))), apply_to = function)
#else
#pragma clang attribute push(__attribute__((target("aes,pclmul"))), apply_to = function)
#endif
#else
#pragma GCC push_options
#ifdef GHASH_VECTOR_ARM
#pragma GCC target("+aes")
#else
#pragma GCC target("aes,pclmul")
#endif
#endif
#endif

// A pass is GHASH_PASS_BLOCKS blocks for both halves of the loop. Each
// loop over the states of a pass carries #pragma GCC unroll 8, which gcc
// and clang both read. gcc 13 at -O2 leaves such a loop rolled and keeps
// the eight states in memory, so every round loads and stores each of
// them: counter mode then took 16.5 µs of a 16 KiB record, against 1.8 µs
// from clang on the same core (docs/performance.md). Unrolled, the states
// stay in registers. gcc does not expand a macro in the pragma, so the
// count is written out and the assertion below holds it to this one.
// ghash_vector.h asserts the same count for GHASH_PASS_BLOCKS.
_Static_assert(GCM_HW_PASS_BLOCKS == 8,
               "each #pragma GCC unroll below writes GCM_HW_PASS_BLOCKS out");
#define GCM_HW_PASS_BYTES ((size_t)GCM_HW_PASS_BLOCKS * AES_BLOCK)

#ifdef GHASH_VECTOR_ARM
typedef uint8x16_t aes_state;
#else
typedef __m128i aes_state;
#endif

// What the seal computes from the key, in one object for one wipe: the
// GHASH state and the pass's counter blocks, which the rounds turn into
// its keystream and the exclusive-or into its output.
typedef struct {
    ghash_state ghash;
    aes_state keystream[GCM_HW_PASS_BLOCKS];
} gcm_hw_state;

// A block moves between memory and a vector register through memcpy
// rather than a pointer cast, so no load assumes the round keys or the
// caller's buffer are 16-byte aligned. Both compilers turn these into
// the unaligned load and store.
static aes_state load_state(const uint8_t p[AES_BLOCK]) {
    aes_state v;
    memcpy(&v, p, AES_BLOCK);
    return v;
}

static void store_state(uint8_t p[AES_BLOCK], aes_state v) {
    memcpy(p, &v, AES_BLOCK);
}

// The rounds of FIPS 197 §5.1 over the eight states of a pass, in three
// steps: pass_start, then pass_round for i from 0 to rounds - 2, then
// pass_final. The two instruction sets place AddRoundKey differently, and
// the three steps hide the difference: each round key is loaded once and
// runs on every state of the pass before the next one is loaded.
#ifdef GHASH_VECTOR_ARM
// vaeseq_u8(s, k) is ShiftRows(SubBytes(s XOR k)) and vaesmcq_u8 is
// MixColumns, so round i takes its AddRoundKey from round key i at its
// front, and the Arm arm has nothing to start with.
static void pass_start(aes_state states[GCM_HW_PASS_BLOCKS], const uint8_t *round_keys) {
    (void)states;
    (void)round_keys;
}

static void pass_round(aes_state states[GCM_HW_PASS_BLOCKS], const uint8_t *round_keys, size_t i) {
    aes_state key = load_state(&round_keys[i * AES_BLOCK]);
#pragma GCC unroll 8
    for (size_t b = 0; b < GCM_HW_PASS_BLOCKS; b++) {
        states[b] = vaesmcq_u8(vaeseq_u8(states[b], key));
    }
}

// The last round drops MixColumns, and its AddRoundKey is the
// exclusive-or of the last round key.
static void pass_final(aes_state states[GCM_HW_PASS_BLOCKS], const uint8_t *round_keys,
                       size_t rounds) {
    aes_state key = load_state(&round_keys[(rounds - 1) * AES_BLOCK]);
    aes_state last = load_state(&round_keys[rounds * AES_BLOCK]);
#pragma GCC unroll 8
    for (size_t b = 0; b < GCM_HW_PASS_BLOCKS; b++) {
        states[b] = veorq_u8(vaeseq_u8(states[b], key), last);
    }
}

// prefix with its bytes 12 to 15 replaced by word: lane 3 of the four
// 32-bit lanes holds those four bytes.
static aes_state counter_state(aes_state prefix, uint32_t word) {
    return vreinterpretq_u8_u32(vsetq_lane_u32(word, vreinterpretq_u32_u8(prefix), 3));
}

static aes_state xor_state(aes_state a, aes_state b) {
    return veorq_u8(a, b);
}
#else
// _mm_aesenc_si128(s, k) is MixColumns(SubBytes(ShiftRows(s))) XOR k, one
// whole round with its AddRoundKey at the end, and _mm_aesenclast_si128
// is the same without MixColumns. So the first AddRoundKey is written out,
// and round i takes round key i + 1.
static void pass_start(aes_state states[GCM_HW_PASS_BLOCKS], const uint8_t *round_keys) {
    aes_state first = load_state(round_keys);
#pragma GCC unroll 8
    for (size_t b = 0; b < GCM_HW_PASS_BLOCKS; b++) {
        states[b] = _mm_xor_si128(states[b], first);
    }
}

static void pass_round(aes_state states[GCM_HW_PASS_BLOCKS], const uint8_t *round_keys, size_t i) {
    aes_state key = load_state(&round_keys[(i + 1) * AES_BLOCK]);
#pragma GCC unroll 8
    for (size_t b = 0; b < GCM_HW_PASS_BLOCKS; b++) {
        states[b] = _mm_aesenc_si128(states[b], key);
    }
}

static void pass_final(aes_state states[GCM_HW_PASS_BLOCKS], const uint8_t *round_keys,
                       size_t rounds) {
    aes_state last = load_state(&round_keys[rounds * AES_BLOCK]);
#pragma GCC unroll 8
    for (size_t b = 0; b < GCM_HW_PASS_BLOCKS; b++) {
        states[b] = _mm_aesenclast_si128(states[b], last);
    }
}

// _mm_cvtsi32_si128 puts word in bytes 0 to 3 of a zero vector, and
// _mm_slli_si128 moves it to bytes 12 to 15, where prefix holds zeros.
static aes_state counter_state(aes_state prefix, uint32_t word) {
    return _mm_or_si128(prefix, _mm_slli_si128(_mm_cvtsi32_si128((int)word), 12));
}

static aes_state xor_state(aes_state a, aes_state b) {
    return _mm_xor_si128(a, b);
}
#endif

// Every round of a pass with nothing between them. Marked inline because
// gcc 13 at -O2 kept one out-of-line copy for its callers, where the round
// keys, which are bytes and so may alias the states, made it store all
// eight states to memory every round (docs/performance.md).
static inline void cipher_pass(aes_state states[GCM_HW_PASS_BLOCKS], const uint8_t *round_keys,
                               size_t rounds) {
    pass_start(states, round_keys);
    for (size_t i = 0; i + 1 < rounds; i++) {
        pass_round(states, round_keys, i);
    }
    pass_final(states, round_keys, rounds);
}

// The four bytes of value, most significant first, as the uint32_t whose
// memory holds them in that order, which is the word counter_state puts
// in bytes 12 to 15. memcpy moves the bytes, so the bytes do not depend
// on the host's byte order.
static uint32_t big_endian_word(uint32_t value) {
    uint8_t bytes[4] = {(uint8_t)(value >> 24), (uint8_t)(value >> 16), (uint8_t)(value >> 8),
                        (uint8_t)value};
    uint32_t word;
    memcpy(&word, bytes, sizeof word);
    return word;
}

// The counter's first twelve bytes, with zeros where the count goes, and
// the count its last four bytes hold, read big-endian.
static aes_state counter_prefix(const uint8_t counter[AES_BLOCK]) {
    uint8_t prefix_bytes[AES_BLOCK] = {0};
    memcpy(prefix_bytes, counter, AES_BLOCK - 4);
    return load_state(prefix_bytes);
}

static uint32_t counter_count(const uint8_t counter[AES_BLOCK]) {
    return ((uint32_t)counter[12] << 24) | ((uint32_t)counter[13] << 16) |
           ((uint32_t)counter[14] << 8) | counter[15];
}

// counter's last four bytes = count, big-endian.
static void set_counter_count(uint8_t counter[AES_BLOCK], uint32_t count) {
    counter[12] = (uint8_t)(count >> 24);
    counter[13] = (uint8_t)(count >> 16);
    counter[14] = (uint8_t)(count >> 8);
    counter[15] = (uint8_t)count;
}

// The pass's counter blocks, first to first + 7, into states. Adding to a
// uint32_t is inc32: the sum wraps modulo 2^32 and never reaches the first
// twelve bytes.
static void fill_counters(aes_state states[GCM_HW_PASS_BLOCKS], aes_state prefix, uint32_t first) {
#pragma GCC unroll 8
    for (size_t b = 0; b < GCM_HW_PASS_BLOCKS; b++) {
        states[b] = counter_state(prefix, big_endian_word(first + (uint32_t)b));
    }
}

// Each block of out is the block of in at the same place exclusive-ored
// with the pass's keystream. A block's input is read before its output is
// written, and an output block ends before the next input block begins
// when out is at or below in.
static void xor_pass(const aes_state keystream[GCM_HW_PASS_BLOCKS], const uint8_t *in, size_t take,
                     uint8_t *out) {
#pragma GCC unroll 8
    for (size_t b = 0; b < take; b++) {
        store_state(&out[b * AES_BLOCK], xor_state(load_state(&in[b * AES_BLOCK]), keystream[b]));
    }
}

// xor_pass over a whole pass, with each block's output written back over
// its keystream too. The keystream is gone as soon as the output is
// written, and states holds the output from then on. Left in states until
// the wipe at the end of the call, the last pass's keystream stayed live
// across the hash that follows it, and clang 18 copied a block of it to a
// stack slot of its own, which the wipe does not clear. Marked inline for
// the reason cipher_pass is: with the seal and the open both calling it,
// gcc 13 at -O2 kept one out-of-line copy, and the call added about a
// third to each loop's time.
static inline void xor_pass_in_place(aes_state states[GCM_HW_PASS_BLOCKS], const uint8_t *in,
                                     uint8_t *out) {
#pragma GCC unroll 8
    for (size_t b = 0; b < GCM_HW_PASS_BLOCKS; b++) {
        states[b] = xor_state(load_state(&in[b * AES_BLOCK]), states[b]);
        store_state(&out[b * AES_BLOCK], states[b]);
    }
}

void gcm_counter_blocks_hw(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                           const uint8_t *in, size_t blocks, uint8_t *out) {
    // No block to run, so no keystream to compute or wipe.
    if (blocks == 0) {
        return;
    }
    aes_state prefix = counter_prefix(counter);
    uint32_t count = counter_count(counter);
    // keystream holds a pass's counter blocks and then their keystream,
    // which the exclusive-or reads. A last pass shorter than
    // GCM_HW_PASS_BLOCKS still runs the rounds on eight counter blocks and
    // uses the ones it needs. One wipe after the loop clears it, however
    // many passes ran, for the case of a copy left on this frame.
    aes_state keystream[GCM_HW_PASS_BLOCKS];
    size_t done = 0;
    while (done < blocks) {
        fill_counters(keystream, prefix, count + (uint32_t)done + 1U);
        cipher_pass(keystream, round_keys, rounds);
        size_t take = blocks - done < GCM_HW_PASS_BLOCKS ? blocks - done : GCM_HW_PASS_BLOCKS;
        xor_pass(keystream, &in[done * AES_BLOCK], take, &out[done * AES_BLOCK]);
        done += take;
    }
    set_counter_count(counter, count + (uint32_t)blocks);
    ct_wipe(keystream, sizeof keystream);
}

void gcm_seal_passes_hw(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                        uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *in,
                        size_t passes, uint8_t *out) {
    if (passes == 0) {
        return;
    }
    gcm_hw_state s;
    s.ghash.subkey = ghash_load_block(subkey);
    s.ghash.acc = ghash_load_block(acc);
    ghash_compute_powers(&s.ghash, GHASH_PASS_BLOCKS);
    aes_state prefix = counter_prefix(counter);
    uint32_t count = counter_count(counter);
    for (size_t p = 0; p < passes; p++) {
        size_t at = p * GCM_HW_PASS_BYTES;
        fill_counters(s.keystream, prefix, count + (uint32_t)(p * GCM_HW_PASS_BLOCKS) + 1U);
        cipher_pass(s.keystream, round_keys, rounds);
        xor_pass_in_place(s.keystream, &in[at], &out[at]);
        // The ciphertext the pass before wrote, which nothing in this pass
        // waits on.
        if (p > 0) {
            ghash_hash_pass(&s.ghash, &out[at - GCM_HW_PASS_BYTES]);
        }
    }
    ghash_hash_pass(&s.ghash, &out[(passes - 1) * GCM_HW_PASS_BYTES]);
    ghash_store_block(acc, s.ghash.acc);
    set_counter_count(counter, count + (uint32_t)(passes * GCM_HW_PASS_BLOCKS));
    ct_wipe(&s, sizeof s);
}

// The seal's loop the other way round. The ciphertext is the input, so a
// pass's GHASH waits on no AES round, and the loop runs one pass ahead:
// iteration p hashes pass p and decrypts pass p - 1. A pass's plaintext is
// written at or below its ciphertext and ends before the next pass's
// ciphertext begins, so the loop hashes every block before it writes a
// plaintext byte to that block's address.
//
// Each step sits in an if of its own, which keeps the compilers from
// mixing the two. With the hash and the rounds in one block, clang 18
// moved the powers' volatile reads up among the AES rounds and copied
// some powers to stack slots of its own, which bin/ghash_equiv_test found.
// With the first pass's hash before the loop, gcc 13 at -O2 built each
// counter from bytes it counted one at a time, and the loop ran about a
// third slower.
void gcm_open_passes_hw(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                        uint8_t acc[AES_BLOCK], const uint8_t subkey[AES_BLOCK], const uint8_t *in,
                        size_t passes, uint8_t *out) {
    if (passes == 0) {
        return;
    }
    gcm_hw_state s;
    s.ghash.subkey = ghash_load_block(subkey);
    s.ghash.acc = ghash_load_block(acc);
    ghash_compute_powers(&s.ghash, GHASH_PASS_BLOCKS);
    aes_state prefix = counter_prefix(counter);
    uint32_t count = counter_count(counter);
    for (size_t p = 0; p <= passes; p++) {
        if (p > 0) {
            size_t at = (p - 1) * GCM_HW_PASS_BYTES;
            fill_counters(s.keystream, prefix,
                          count + (uint32_t)((p - 1) * GCM_HW_PASS_BLOCKS) + 1U);
            cipher_pass(s.keystream, round_keys, rounds);
            xor_pass_in_place(s.keystream, &in[at], &out[at]);
        }
        if (p < passes) {
            ghash_hash_pass(&s.ghash, &in[p * GCM_HW_PASS_BYTES]);
        }
    }
    ghash_store_block(acc, s.ghash.acc);
    set_counter_count(counter, count + (uint32_t)(passes * GCM_HW_PASS_BLOCKS));
    ct_wipe(&s, sizeof s);
}

#ifdef CH_AES_RUNTIME
#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif
#endif

#endif // CH_AES_HW || CH_AES_RUNTIME
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
