// AES=hw: the AES-128 key expansion and forward cipher of FIPS 197 on
// the AES instructions, through the compiler's own intrinsic headers,
// counter mode over whole blocks, BLOCKS_PER_PASS blocks at a time, and
// the three AES-256 entries in a build that has AES-256 (CH_AES_256,
// aes.h).
// aes_block.h states the contracts; this file implements them and
// nothing else. Both key sizes share one expansion loop, one round loop
// and one counter loop, so AES-256 adds three entries and no second
// cipher.
//
// Two instruction sets, and the compiler picks between them at build
// time. __ARM_FEATURE_AES says the ARMv8 crypto extensions are available
// and <arm_neon.h> declares vaeseq_u8 and vaesmcq_u8; __AES__ says
// x86-64 AES-NI is available and <wmmintrin.h> declares
// _mm_aesenc_si128, _mm_aesenclast_si128 and _mm_aeskeygenassist_si128.
// A build that defines neither gets the #error below rather than a
// silent fall back to the table, because AES=hw is a statement about
// what the object contains.
//
// Nothing here probes a CPU and nothing here calls an operating system,
// and that is deliberate rather than a preference. An arm64 core cannot
// answer the question itself: reading ID_AA64ISAR0_EL1 from EL0 takes
// SIGILL. So runtime detection means asking the operating system, which
// is per-OS code this tree cannot carry under its C11-and-libc rule, and
// which the bare-metal m3 and freertos lanes have nobody to ask. A
// consumer compiles chapulin into its own build, so it already chooses
// -march=armv8-a+crypto or -maes; a build without the flag takes
// AES=soft and stays correct, and a consumer that probes the CPU itself
// takes AES=runtime and passes the answer.
//
// AES=runtime compiles this file with no instruction flag, so the rest of
// the object runs on any CPU of its architecture. The architecture picks
// the instruction set, and the pragma below puts the target attribute
// that turns the AES instructions on onto each function in this file and
// on no function outside it. aes.c calls this file for a traffic key, and
// for a public key only when the caller's probe found the instructions
// (ch_cfg.aes_instructions), so a session whose CPU lacks them never
// runs a line of it (docs/decisions.md 81).
//
// The intrinsic headers are the compiler's own, so they are not third-
// party code. A third-party AES library would be.
//
// This file reads no table, which is the one timing property it can state
// for itself: quic_aes_soft.c indexes a 256-byte S-box with cipher state,
// and no line here indexes anything with an operand.
//
// It cannot state the rest. __ARM_FEATURE_AES and __AES__ say the AES
// instructions exist. Neither says the instructions take the same number of
// cycles whatever their operands are, and the architectures do not promise
// it either: Arm publishes FEAT_DIT and Intel publishes DOITM precisely
// because the base architectures leave instruction timing to the
// implementation. ct.h refuses the same inference for the widening
// multiply, in the same words, and asks the build to assert what the
// preprocessor cannot read (https://github.com/c4milo/chapulin/issues/53).
//
// So one macro carries that claim here, and it is the build's to make:
//
//   CH_NATIVE_AES  the build asserts that this part's AES instructions
//                  run in constant time, and so does the carry-less
//                  multiply ghash_hw.c runs GHASH on, the other half
//                  of an AES=hw object. Firmware defines it only with a
//                  vendor statement that covers both, the way it defines
//                  CH_NATIVE_WIDEMUL. Nothing in this file reads it.
//
// ct.h reads it, and only in a build that declares -DCH_SUITE_AES_GCM:
// the two AES-GCM cipher suites hand this file a traffic key, AES-128
// or AES-256, and that build without CH_NATIVE_AES is a compile error
// rather than an object whose timing nobody stated. Every other build
// hands it only the three public keys INV-26 names, whose timing leaks
// nothing an observer does not already hold.
//
// CBMC cannot read an intrinsic, so the proofs stay on the software path
// and this file is held to it by test/aes_equiv_test.c, which runs both
// implementations over the same inputs and compares byte for byte.
#include "aes_block.h"

#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#if defined(CH_AES_HW) || defined(CH_AES_RUNTIME)

#include <stddef.h>
#include <string.h>

#include "ct.h"

// Which instruction set the arms below take: the Arm AES instructions
// where AES_HW_ARM is defined, and x86-64 AES-NI where it is not. Under
// AES=hw the build's flags say which, and under AES=runtime the
// architecture does, because no flag turns the instructions on.
#ifdef CH_AES_RUNTIME
#ifdef __aarch64__
#define AES_HW_ARM
#elif !defined(__x86_64__)
#error "AES=runtime needs an arm64 or x86-64 target, whose AES instructions it can run"
#endif
#elif defined(__ARM_FEATURE_AES)
#define AES_HW_ARM
#elif !defined(__AES__)
#error                                                                                             \
    "AES=hw needs the AES instructions: compile with -march=armv8-a+crypto or -maes, or build AES=soft"
#endif

#ifdef AES_HW_ARM
#include <arm_neon.h>
typedef uint8x16_t aes_state;
#else
#include <wmmintrin.h>
typedef __m128i aes_state;
#endif

// How many counter blocks aes_counter_blocks runs through the rounds
// together. The rounds of one block do not depend on another block's, so
// the core can run the eight at once. Eight states and one round key take
// nine vector registers, which x86-64's sixteen and arm64's thirty-two
// both hold.
//
// Each loop over the states of a pass carries #pragma GCC unroll 8, which
// gcc and clang both read. gcc 13 at -O2 leaves such a loop rolled and
// keeps the eight states in memory, so every round loads and stores each
// of them: counter mode then took 16.5 µs of a 16 KiB record, against 1.8
// µs from clang on the same core (docs/performance.md). Unrolled, the
// states stay in registers. gcc does not expand a macro in the pragma, so
// the count is written out and the assertion below holds it to this one.
#define BLOCKS_PER_PASS 8
_Static_assert(BLOCKS_PER_PASS == 8, "each #pragma GCC unroll below writes BLOCKS_PER_PASS out");

// Under AES=runtime, every function from here to the pop at the end of
// this file carries the target attribute that turns the AES instructions
// on: "+aes" is the Arm AES extension, and "aes" is x86-64 AES-NI. GCC's
// target pragma applies the attribute to each function defined after it,
// and clang's attribute pragma to each function it covers, so the
// includes above and every other file of the object stay without it.
#ifdef CH_AES_RUNTIME
#ifdef __clang__
#ifdef AES_HW_ARM
#pragma clang attribute push(__attribute__((target("+aes"))), apply_to = function)
#else
#pragma clang attribute push(__attribute__((target("aes"))), apply_to = function)
#endif
#else
#pragma GCC push_options
#ifdef AES_HW_ARM
#pragma GCC target("+aes")
#else
#pragma GCC target("aes")
#endif
#endif
#endif

// A block moves between memory and a vector register through memcpy
// rather than a pointer cast, so no load assumes the round keys or the
// caller's buffer are 16-byte aligned. Both compilers turn these into
// the unaligned load and store.
static aes_state load_block(const uint8_t p[AES_BLOCK]) {
    aes_state v;
    memcpy(&v, p, AES_BLOCK);
    return v;
}

static void store_block(uint8_t p[AES_BLOCK], aes_state v) {
    memcpy(p, &v, AES_BLOCK);
}

// FIPS 197 §5.2's SubWord: the S-box applied to each of 4 bytes. Both
// instruction sets reach it as a by-product of an instruction built for
// something else, so neither arm reads a table.
//
// The bytes travel into the vector and back through memcpy, so this does
// not assume host endianness: the same representation is packed and
// unpacked, and SubWord treats each byte on its own, so no step depends
// on which end a word starts at.
#ifdef AES_HW_ARM
static void sub_word(const uint8_t in[4], uint8_t out[4]) {
    // vaeseq_u8(v, zero) is ShiftRows(SubBytes(v)). Replicating the word
    // into all four columns makes ShiftRows move equal bytes between
    // equal columns, so what comes back is SubBytes alone, and column 0
    // holds SubWord of the input word.
    uint32_t word;
    memcpy(&word, in, 4);
    uint8x16_t replicated = vreinterpretq_u8_u32(vdupq_n_u32(word));
    uint8x16_t substituted = vaeseq_u8(replicated, vdupq_n_u8(0));
    memcpy(out, &substituted, 4);
}
#else
static void sub_word(const uint8_t in[4], uint8_t out[4]) {
    // _mm_aeskeygenassist_si128(v, rcon) writes SubWord of v's second
    // dword into its first. Replicating the word into all four dwords
    // therefore puts SubWord of the input word in dword 0, and a round
    // constant of 0 leaves that dword alone.
    uint32_t word;
    memcpy(&word, in, 4);
    __m128i replicated = _mm_set1_epi32((int)word);
    __m128i substituted = _mm_aeskeygenassist_si128(replicated, 0);
    memcpy(out, &substituted, 4);
}
#endif

// One multiplication by x in GF(2^8), FIPS 197 §4.2, which is how the
// round constant advances. quic_aes_soft.c states the mask.
static uint8_t xtime(uint8_t b) {
    uint8_t high_set = (uint8_t)(0U - (unsigned)(b >> 7)); // 0xff when bit 7 was set, else 0
    return (uint8_t)(((unsigned)b << 1) ^ (0x1bU & high_set));
}

// FIPS 197 §5.2 for either key size, the same expansion quic_aes_soft.c
// writes, with the instruction-backed SubWord above in place of the table
// lookup. The two files agree byte for byte, which test/aes_equiv_test.c
// checks. key_len is AES_128_KEY (Nk = 4) or AES_256_KEY (Nk = 8) and
// schedule_len is the bytes of round keys that size fills; both are the
// entry's own constants, never an operand, so every branch below reads
// a public value.
//
// Each word is the word key_len bytes back exclusive-ored with a
// temporary. The temporary is the word before it, which every key_len-th
// byte takes RotWord, SubWord and the round constant first, and which
// AES-256 alone also passes through SubWord halfway between two of those
// (FIPS 197 §5.2, the Nk > 6 step).
static void expand(const uint8_t *key, size_t key_len, uint8_t *round_keys, size_t schedule_len) {
    uint8_t round_constant = 0x01;
    memcpy(round_keys, key, key_len);
    uint8_t word[4];
    uint8_t substituted[4] = {0};
    for (size_t i = key_len; i < schedule_len; i += 4) {
        memcpy(word, &round_keys[i - 4], sizeof word);
        if (i % key_len == 0) {
            sub_word(word, substituted);
            // RotWord, then the round constant on the first byte.
            word[0] = (uint8_t)(substituted[1] ^ round_constant);
            word[1] = substituted[2];
            word[2] = substituted[3];
            word[3] = substituted[0];
            round_constant = xtime(round_constant);
        } else if (key_len == AES_256_KEY && i % key_len == AES_BLOCK) {
            sub_word(word, substituted);
            memcpy(word, substituted, sizeof word);
        }
        for (size_t j = 0; j < sizeof word; j++) {
            round_keys[i + j] = (uint8_t)(round_keys[i - key_len + j] ^ word[j]);
        }
    }
    // Both temporaries hold bytes of the last round key. Under
    // -DCH_SUITE_AES_GCM that is a traffic key, and this is the one
    // implementation that build runs a traffic key on, so the wipe runs
    // here and not in quic_aes_soft.c. Two calls and two fixed sizes, so
    // the wipe itself reads nothing it was given.
    ct_wipe(word, sizeof word);
    ct_wipe(substituted, sizeof substituted);
}

void aes_expand_round_keys(const uint8_t key[AES_128_KEY],
                           uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK]) {
    expand(key, AES_128_KEY, round_keys, (size_t)AES_ROUND_KEYS * AES_BLOCK);
}

#ifdef AES_HW_ARM
// FIPS 197 §5.1 over rounds rounds, AES_128_ROUNDS or AES_256_ROUNDS, a
// constant each entry below passes. vaeseq_u8(s, k) is
// ShiftRows(SubBytes(s XOR k)) and vaesmcq_u8 is MixColumns, so each pair
// below is one round with its AddRoundKey taken from the front of the
// next instruction. The last round drops MixColumns and its AddRoundKey
// is the exclusive-or that follows.
static void cipher(const uint8_t *round_keys, size_t rounds, const uint8_t in[AES_BLOCK],
                   uint8_t out[AES_BLOCK]) {
    aes_state state = load_block(in);
    for (size_t round = 0; round < rounds - 1; round++) {
        state = vaeseq_u8(state, load_block(&round_keys[round * AES_BLOCK]));
        state = vaesmcq_u8(state);
    }
    state = vaeseq_u8(state, load_block(&round_keys[(rounds - 1) * AES_BLOCK]));
    state = veorq_u8(state, load_block(&round_keys[rounds * AES_BLOCK]));
    store_block(out, state);
    // state holds the block this call produced, which under AES-GCM is one
    // block of keystream. out already holds it, so the wipe removes the
    // copy this frame would leave behind.
    ct_wipe(&state, sizeof state);
}

// cipher over BLOCKS_PER_PASS states at once, round by round: each round
// key is loaded once and runs on every state of the pass before the next
// one is loaded.
static void cipher_pass(const uint8_t *round_keys, size_t rounds,
                        aes_state states[BLOCKS_PER_PASS]) {
    for (size_t round = 0; round < rounds - 1; round++) {
        aes_state key = load_block(&round_keys[round * AES_BLOCK]);
#pragma GCC unroll 8
        for (size_t b = 0; b < BLOCKS_PER_PASS; b++) {
            states[b] = vaesmcq_u8(vaeseq_u8(states[b], key));
        }
    }
    aes_state key = load_block(&round_keys[(rounds - 1) * AES_BLOCK]);
    aes_state last = load_block(&round_keys[rounds * AES_BLOCK]);
#pragma GCC unroll 8
    for (size_t b = 0; b < BLOCKS_PER_PASS; b++) {
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
// The same over the x86-64 instructions. _mm_aesenc_si128(s, k) is
// MixColumns(SubBytes(ShiftRows(s))) XOR k, one whole FIPS 197 §5.1 round
// with its AddRoundKey at the end, and _mm_aesenclast_si128 is the same
// without MixColumns. So the first AddRoundKey is written out and the
// rounds follow it.
static void cipher(const uint8_t *round_keys, size_t rounds, const uint8_t in[AES_BLOCK],
                   uint8_t out[AES_BLOCK]) {
    aes_state state = load_block(in);
    state = _mm_xor_si128(state, load_block(round_keys));
    for (size_t round = 1; round < rounds; round++) {
        state = _mm_aesenc_si128(state, load_block(&round_keys[round * AES_BLOCK]));
    }
    state = _mm_aesenclast_si128(state, load_block(&round_keys[rounds * AES_BLOCK]));
    store_block(out, state);
    // The arm above states why.
    ct_wipe(&state, sizeof state);
}

// The same three over the x86-64 instructions.
static void cipher_pass(const uint8_t *round_keys, size_t rounds,
                        aes_state states[BLOCKS_PER_PASS]) {
    aes_state first = load_block(round_keys);
#pragma GCC unroll 8
    for (size_t b = 0; b < BLOCKS_PER_PASS; b++) {
        states[b] = _mm_xor_si128(states[b], first);
    }
    for (size_t round = 1; round < rounds; round++) {
        aes_state key = load_block(&round_keys[round * AES_BLOCK]);
#pragma GCC unroll 8
        for (size_t b = 0; b < BLOCKS_PER_PASS; b++) {
            states[b] = _mm_aesenc_si128(states[b], key);
        }
    }
    aes_state last = load_block(&round_keys[rounds * AES_BLOCK]);
#pragma GCC unroll 8
    for (size_t b = 0; b < BLOCKS_PER_PASS; b++) {
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

void aes_cipher_block(const uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK],
                      const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    cipher(round_keys, AES_128_ROUNDS, in, out);
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

// SP 800-38D §6.5's GCTR over whole blocks, aes_block.h's contract for
// aes_counter_blocks, BLOCKS_PER_PASS counter blocks per pass. count is
// the counter's last four bytes read big-endian, and adding to a uint32_t
// is inc32: the sum wraps modulo 2^32 and never reaches the first twelve
// bytes. A last pass shorter than BLOCKS_PER_PASS still runs the rounds
// on BLOCKS_PER_PASS counter blocks and uses the ones it needs.
//
// Each block's input is read before its output is written, and an output
// block ends before the next input block begins when out is at or below
// in, so both overlaps the contract admits read every input byte first.
static void counter_blocks(const uint8_t *round_keys, size_t rounds, uint8_t counter[AES_BLOCK],
                           const uint8_t *in, size_t blocks, uint8_t *out) {
    uint8_t prefix_bytes[AES_BLOCK] = {0};
    memcpy(prefix_bytes, counter, AES_BLOCK - 4);
    aes_state prefix = load_block(prefix_bytes);
    uint32_t count = ((uint32_t)counter[12] << 24) | ((uint32_t)counter[13] << 16) |
                     ((uint32_t)counter[14] << 8) | counter[15];
    // keystream holds a pass's counter blocks and then their keystream,
    // which the exclusive-or reads. Every loop over it that runs the rounds
    // is unrolled, so the compiler can keep it in registers through them.
    // One wipe after the loop clears it, however many passes ran, for the
    // case of a copy left on this frame, as cipher wipes its state.
    aes_state keystream[BLOCKS_PER_PASS];
    size_t done = 0;
    while (done < blocks) {
#pragma GCC unroll 8
        for (size_t b = 0; b < BLOCKS_PER_PASS; b++) {
            keystream[b] = counter_state(prefix, big_endian_word(count + (uint32_t)(done + b + 1)));
        }
        cipher_pass(round_keys, rounds, keystream);
        size_t take = blocks - done < BLOCKS_PER_PASS ? blocks - done : BLOCKS_PER_PASS;
        for (size_t b = 0; b < take; b++) {
            size_t at = (done + b) * AES_BLOCK;
            store_block(&out[at], xor_state(load_block(&in[at]), keystream[b]));
        }
        done += take;
    }
    uint32_t last = count + (uint32_t)blocks;
    counter[12] = (uint8_t)(last >> 24);
    counter[13] = (uint8_t)(last >> 16);
    counter[14] = (uint8_t)(last >> 8);
    counter[15] = (uint8_t)last;
    ct_wipe(keystream, sizeof keystream);
}

void aes_counter_blocks(const uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK],
                        uint8_t counter[AES_BLOCK], const uint8_t *in, size_t blocks,
                        uint8_t *out) {
    counter_blocks(round_keys, AES_128_ROUNDS, counter, in, blocks, out);
}

#ifdef CH_AES_256
// AES-256, the cipher of TLS_AES_256_GCM_SHA384. A library object compiles
// it only under -DCH_SUITE_AES_GCM; test/aes_equiv_hw.c compiles it to
// hold it to the software reference.
void aes_expand_round_keys_256(const uint8_t key[AES_256_KEY],
                               uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK]) {
    expand(key, AES_256_KEY, round_keys, (size_t)AES_256_ROUND_KEYS * AES_BLOCK);
}

void aes_cipher_block_256(const uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK],
                          const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    cipher(round_keys, AES_256_ROUNDS, in, out);
}

void aes_counter_blocks_256(const uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK],
                            uint8_t counter[AES_BLOCK], const uint8_t *in, size_t blocks,
                            uint8_t *out) {
    counter_blocks(round_keys, AES_256_ROUNDS, counter, in, blocks, out);
}
#endif

#ifdef CH_AES_RUNTIME
#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif
#endif

#endif // CH_AES_HW || CH_AES_RUNTIME
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
