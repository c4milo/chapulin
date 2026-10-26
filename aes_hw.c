// The AES instructions: the AES-128 key expansion and forward cipher of
// FIPS 197 on them, through the compiler's own intrinsic headers, and the
// two AES-256 entries in a build that has AES-256 (CH_AES_256, aes.h). A
// host object (-DCH_CPU_RUNTIME, cpu_cfg.h) compiles this file whenever
// it carries AES. aes_block.h states the contracts; this file implements
// them and nothing else. Both key sizes share one round loop, so AES-256
// adds two entries and no second cipher. Counter mode over whole blocks,
// several at a time, is gcm_hw.c's.
//
// Two instruction sets, and the architecture picks between them: the
// ARMv8 crypto extensions on arm64, through <arm_neon.h>'s vaeseq_u8 and
// vaesmcq_u8, and AES-NI on x86-64, through <wmmintrin.h>'s
// _mm_aesenc_si128 and _mm_aesenclast_si128. cpu_cfg.h refuses a host
// object for any other target. Both compute a key schedule a round key at
// a time in vector registers, in one function per key size, over four
// helpers that each architecture writes in its own instructions.
//
// The object compiles this file with no instruction flag, so the rest of
// the object runs on any CPU of its architecture. The pragma below puts
// the target attribute that turns the AES instructions on onto each
// function in this file and on no function outside it. aes.c calls this
// file for a traffic key, and for a public key only when the session's
// caller set CH_CPU_CONSTANT_TIME_AES, so a session without that bit
// never runs a line of it (docs/decisions.md 81 and 89).
//
// Nothing here probes a CPU and nothing here calls an operating system,
// and that is deliberate rather than a preference. An arm64 core cannot
// answer the question itself: reading ID_AA64ISAR0_EL1 from EL0 takes
// SIGILL. So detection means asking the operating system, which is
// per-OS code this tree cannot carry under its C11-and-libc rule, and
// which the bare-metal m3 and freertos lanes have nobody to ask. The
// caller probes the CPU and states what it found in ch_cfg.cpu.
//
// The intrinsic headers are the compiler's own, so they are not third-
// party code. A third-party AES library would be.
//
// This file reads no table, which is the one timing property it can state
// for itself: quic_aes_soft.c indexes a 256-byte S-box with cipher state,
// and no line here indexes anything with an operand.
//
// It cannot state the rest. That the instructions exist says nothing
// about whether they take the same number of cycles whatever their
// operands are, and the architectures do not promise it either: Arm
// publishes FEAT_DIT and Intel publishes DOITM precisely because the base
// architectures leave instruction timing to the implementation. ct.h
// refuses the same inference for the widening multiply, in the same
// words (https://github.com/c4milo/chapulin/issues/53).
//
// So one bit carries that claim, and it is the caller's to make, for the
// CPU and the mode each session's thread runs in: CH_CPU_CONSTANT_TIME_AES
// (cpu_cfg.h) states that the AES instructions run in constant time, and
// so does the carry-less multiply ghash_hw.c runs GHASH on. Nothing in
// this file reads it. A session takes the AES-GCM suites, and so hands
// this file a traffic key, AES-128 or AES-256, only with the bit; every
// other key this file sees is one of the three public keys INV-26 names,
// whose timing leaks nothing an observer does not already hold.
//
// CBMC cannot read an intrinsic, so the proofs stay on the software path
// and this file is held to it by test/aes_equiv_test.c, which runs both
// implementations over the same inputs and compares byte for byte, and
// searches the stack each key expansion leaves for a word the expansion
// computed (test/aes_equiv_residue.h).
#include "aes_block.h"

#if defined(CH_TRANSPORT_QUIC_NONBLOCKING) || defined(CH_SUITE_AES_GCM)
#ifdef CH_CPU_RUNTIME

#include <stddef.h>
#include <string.h>

#include "ct.h"

// Which instruction set the arms below take: the Arm AES instructions
// where AES_HW_ARM is defined, and x86-64 AES-NI where it is not. The
// architecture says which, because no flag turns the instructions on, and
// cpu_cfg.h has refused every target but these two.
#ifdef __aarch64__
#define AES_HW_ARM
#endif

#ifdef AES_HW_ARM
#include <arm_neon.h>
typedef uint8x16_t aes_state;
#else
#include <wmmintrin.h>
typedef __m128i aes_state;
#endif

// Every function from here to the pop at the end of this file carries
// the target attribute that turns the AES instructions on: "+aes" is the
// Arm AES extension, and "aes" is x86-64 AES-NI. GCC's target pragma
// applies the attribute to each function defined after it, and clang's
// attribute pragma to each function it covers, so the includes above and
// every other file of the object stay without it.
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

// A block moves between memory and a vector register with no assumption
// that the round keys or the caller's buffer are 16-byte aligned. On
// arm64 memcpy moves it, which both compilers turn into the unaligned
// load and store. On x86-64 the unaligned load and store intrinsics move
// it, as ghash_vector.h's do: gcc 13 at -O3 compiled the memcpy of a key
// into a register as a store of the key to a stack slot and a load of its
// upper half back from the slot, and nothing wiped the slot
// (test/aes_equiv_residue.h). __m128i may alias any type, so the casts
// read and write the bytes as they lie.
#ifdef AES_HW_ARM
static inline __attribute__((always_inline)) aes_state load_block(const uint8_t p[AES_BLOCK]) {
    aes_state v;
    memcpy(&v, p, AES_BLOCK);
    return v;
}

static inline __attribute__((always_inline)) void store_block(uint8_t p[AES_BLOCK], aes_state v) {
    memcpy(p, &v, AES_BLOCK);
}
#else
static inline __attribute__((always_inline)) aes_state load_block(const uint8_t p[AES_BLOCK]) {
    return _mm_loadu_si128((const __m128i *)(const void *)p);
}

static inline __attribute__((always_inline)) void store_block(uint8_t p[AES_BLOCK], aes_state v) {
    _mm_storeu_si128((__m128i *)(void *)p, v);
}
#endif

// One multiplication by x in GF(2^8), FIPS 197 §4.2, which is how the
// round constant advances. quic_aes_soft.c states the mask.
static inline __attribute__((always_inline)) uint8_t xtime(uint8_t b) {
    uint8_t high_set = (uint8_t)(0U - (unsigned)(b >> 7)); // 0xff when bit 7 was set, else 0
    return (uint8_t)(((unsigned)b << 1) ^ (0x1bU & high_set));
}

// FIPS 197 §5.2 a round key at a time, on both architectures. Each round
// key is one vector value, computed from the round keys before it and
// stored to round_keys once, and nothing reads the schedule back. A word
// loop, which ran each SubWord on a word copied into a vector register
// and back out and read each word back from round_keys, took 10 to 21
// times as long on x86-64 (docs/decisions.md 123) and 196 ns of an M1
// Pro's 2.33 µs AES-128-GCM record of 16 KiB on arm64
// (docs/decisions.md 158). Every loop below runs a count the key size
// fixes, so every branch reads a public value.
//
// The C holds no array to wipe, and test/aes_equiv_residue.h checks that
// the compilers add no stack slot. Every function the expansion calls is
// always inlined, the helpers below, load_block, store_block and xtime, so
// the expansion makes no call: x86-64's calling convention keeps no
// vector register across a call, and arm64's keeps only the low half of
// eight of them. gcc 13 at -Os, which left one helper out of line on
// x86-64, kept a round key in a stack slot across each call to it.
//
// Each word of a new round key is the word Nk words back exclusive-ored
// with the word before it, and the first word takes a temporary in place
// of the word before it. Unrolled over a round key of four words, word i
// of the new round key is the temporary exclusive-ored with words 0 to i
// of the round key Nk words back: prefix_xor of that round key, with the
// temporary exclusive-ored into all four words.
//
// Four helpers differ between the architectures: prefix_xor,
// rot_sub_last_word, sub_last_word and round_constant_words. Byte i of a
// block is byte lane i of its vector on both, so a helper that moves bytes
// names byte lanes.
#ifdef AES_HW_ARM
// Each word i of v becomes the exclusive-or of v's words 0 to i.
// vextq_u8(zero, v, 12) is v moved up 4 byte lanes, with zeros in lanes 0
// to 3, which moves each word up one place, and vextq_u8(zero, v, 8)
// moves each word up two places.
static inline __attribute__((always_inline)) aes_state prefix_xor(aes_state v) {
    aes_state zero = vdupq_n_u8(0);
    v = veorq_u8(v, vextq_u8(zero, v, 12));
    return veorq_u8(v, vextq_u8(zero, v, 8));
}

// The 16 byte lanes vqtbl1q_u8 reads for rot_sub_last_word and
// sub_last_word: word 3's bytes (a0, a1, a2, a3), in lanes 12 to 15, as
// (a1, a2, a3, a0) in each of the four words, which is RotWord, and as
// themselves in each word.
static const uint8_t ROT_LAST_WORD_LANES[AES_BLOCK] = {13, 14, 15, 12, 13, 14, 15, 12,
                                                       13, 14, 15, 12, 13, 14, 15, 12};
#ifdef CH_AES_256
static const uint8_t LAST_WORD_LANES[AES_BLOCK] = {12, 13, 14, 15, 12, 13, 14, 15,
                                                   12, 13, 14, 15, 12, 13, 14, 15};
#endif

// SubWord of RotWord of v's last word, word 3, in all four words. The
// table lookup copies the word, rotated, into all four words, and
// vaeseq_u8(s, zero) is ShiftRows(SubBytes(s)): with four equal columns
// ShiftRows moves equal bytes between equal columns, so what comes back
// is SubBytes alone. The lanes the lookup reads are constants, so no
// operand picks an address.
static inline __attribute__((always_inline)) aes_state rot_sub_last_word(aes_state v) {
    return vaeseq_u8(vqtbl1q_u8(v, vld1q_u8(ROT_LAST_WORD_LANES)), vdupq_n_u8(0));
}

#ifdef CH_AES_256
static inline __attribute__((always_inline)) aes_state sub_last_word(aes_state v) {
    return vaeseq_u8(vqtbl1q_u8(v, vld1q_u8(LAST_WORD_LANES)), vdupq_n_u8(0));
}
#endif

// The round constant in byte 0 of each word and zeros elsewhere: the
// constant in all 16 lanes, kept in the lanes the mask keeps.
static const uint8_t FIRST_BYTE_OF_EACH_WORD[AES_BLOCK] = {0xff, 0, 0, 0, 0xff, 0, 0, 0,
                                                           0xff, 0, 0, 0, 0xff, 0, 0, 0};

static inline __attribute__((always_inline)) aes_state round_constant_words(uint8_t constant) {
    return vandq_u8(vdupq_n_u8(constant), vld1q_u8(FIRST_BYTE_OF_EACH_WORD));
}

static inline __attribute__((always_inline)) aes_state xor_block(aes_state a, aes_state b) {
    return veorq_u8(a, b);
}
#else
// x86-64 is little-endian, so byte 0 of a word, the byte FIPS 197 writes
// first, is bits 0 to 7 of its 32-bit lane.

// Each word i of v becomes the exclusive-or of v's words 0 to i. The
// shift by 4 bytes moves each word up one place and puts a zero in word
// 0, and the shift by 8 bytes moves each word up two places.
static inline __attribute__((always_inline)) aes_state prefix_xor(aes_state v) {
    v = _mm_xor_si128(v, _mm_slli_si128(v, 4));
    return _mm_xor_si128(v, _mm_slli_si128(v, 8));
}

// SubWord of v's last word, word 3, in all four words. The shuffle copies
// word 3 into all four words, and _mm_aesenclast_si128(s, zero) is
// SubBytes(ShiftRows(s)): with four equal columns ShiftRows moves equal
// bytes between equal columns, so what comes back is SubBytes alone.
static inline __attribute__((always_inline)) aes_state sub_last_word(aes_state v) {
    return _mm_aesenclast_si128(_mm_shuffle_epi32(v, 0xff), _mm_setzero_si128());
}

// RotWord of SubWord of v's last word in all four words. RotWord turns
// the bytes (a0, a1, a2, a3) into (a1, a2, a3, a0), which in a
// little-endian lane is a rotation right by 8 bits. SubWord treats each
// byte alone, so this is SubWord of RotWord too.
static inline __attribute__((always_inline)) aes_state rot_sub_last_word(aes_state v) {
    aes_state w = sub_last_word(v);
    return _mm_or_si128(_mm_srli_epi32(w, 8), _mm_slli_epi32(w, 24));
}

// The round constant in the low byte of each 32-bit lane, which is byte 0
// of each word.
static inline __attribute__((always_inline)) aes_state round_constant_words(uint8_t constant) {
    return _mm_set1_epi32((int)constant);
}

static inline __attribute__((always_inline)) aes_state xor_block(aes_state a, aes_state b) {
    return _mm_xor_si128(a, b);
}
#endif

// The round key after before, by the step every Nk-th word takes: the
// temporary is RotWord(SubWord(w)) exclusive-ored with the round constant
// on its first byte, w the last word of before. key is the round key Nk
// words back: AES-128 passes before as key, and AES-256 the round key
// before before.
static inline __attribute__((always_inline)) aes_state next_round_key(aes_state key,
                                                                      aes_state before,
                                                                      uint8_t round_constant) {
    aes_state temporary =
        xor_block(rot_sub_last_word(before), round_constant_words(round_constant));
    return xor_block(prefix_xor(key), temporary);
}

#ifdef CH_AES_256
// AES-256's round key after first, a round key next_round_key wrote, by
// the step the word four after every eighth takes: the temporary is
// SubWord of first's last word, with no RotWord and no round constant.
// key is the round key before first. expand_256 alone calls it, so it
// sits under the same define: clang's -Wunused-function names an unused
// static inline function, and -Werror makes that an error.
static inline __attribute__((always_inline)) aes_state next_second_round_key(aes_state key,
                                                                             aes_state first) {
    return xor_block(prefix_xor(key), sub_last_word(first));
}
#endif

static void expand_128(const uint8_t key[AES_128_KEY], uint8_t *round_keys) {
    aes_state round_key = load_block(key);
    store_block(round_keys, round_key);
    uint8_t round_constant = 0x01;
    for (size_t i = 1; i < AES_ROUND_KEYS; i++) {
        round_key = next_round_key(round_key, round_key, round_constant);
        store_block(&round_keys[i * AES_BLOCK], round_key);
        round_constant = xtime(round_constant);
    }
}

#ifdef CH_AES_256
// Round keys 0 and 1 are the key's two halves. Each pass of the loop
// writes the next two, from 2 and 3 up to 12 and 13, and round key 14,
// the last, takes next_round_key's step alone.
static void expand_256(const uint8_t key[AES_256_KEY], uint8_t *round_keys) {
    aes_state first = load_block(key);
    aes_state second = load_block(&key[AES_BLOCK]);
    store_block(round_keys, first);
    store_block(&round_keys[AES_BLOCK], second);
    uint8_t round_constant = 0x01;
    for (size_t i = 2; i < AES_256_ROUND_KEYS - 1; i += 2) {
        first = next_round_key(first, second, round_constant);
        second = next_second_round_key(second, first);
        store_block(&round_keys[i * AES_BLOCK], first);
        store_block(&round_keys[(i + 1) * AES_BLOCK], second);
        round_constant = xtime(round_constant);
    }
    first = next_round_key(first, second, round_constant);
    store_block(&round_keys[(size_t)(AES_256_ROUND_KEYS - 1) * AES_BLOCK], first);
}
#endif

void aes_expand_round_keys(const uint8_t key[AES_128_KEY],
                           uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK]) {
    expand_128(key, round_keys);
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

#endif

void aes_cipher_block(const uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK],
                      const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    cipher(round_keys, AES_128_ROUNDS, in, out);
}

#ifdef CH_AES_256
// AES-256, the cipher of TLS_AES_256_GCM_SHA384. A library object compiles
// it only under -DCH_SUITE_AES_GCM; test/aes_equiv_hw.c compiles it to
// hold it to the software reference.
void aes_expand_round_keys_256(const uint8_t key[AES_256_KEY],
                               uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK]) {
    expand_256(key, round_keys);
}

void aes_cipher_block_256(const uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK],
                          const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    cipher(round_keys, AES_256_ROUNDS, in, out);
}

#endif

#ifdef __clang__
#pragma clang attribute pop
#else
#pragma GCC pop_options
#endif

#endif // CH_CPU_RUNTIME
#endif // CH_TRANSPORT_QUIC_NONBLOCKING || CH_SUITE_AES_GCM
