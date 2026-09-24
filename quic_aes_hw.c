// AES=hw: the AES-128 key expansion and forward cipher of FIPS 197 on
// the AES instructions, through the compiler's own intrinsic headers.
// quic_aes_block.h states both contracts; this file implements them and
// nothing else.
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
// AES=soft and stays correct.
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
//                  multiply quic_ghash_hw.c runs GHASH on, the other half
//                  of an AES=hw object. Firmware defines it only with a
//                  vendor statement that covers both, the way it defines
//                  CH_NATIVE_WIDEMUL. Nothing in this file reads it.
//
// Nothing reads it because nothing here needs it: INV-26 admits only the
// three public keys RFC 9001 fixes, and their timing leaks nothing an
// observer does not already hold. ct.h is what reads it, and only in a
// build that declares -DCH_SUITE_AES_GCM: a cipher suite hands this file a
// traffic key, and that build without CH_NATIVE_AES is a compile error
// rather than an object whose timing nobody stated.
//
// CBMC cannot read an intrinsic, so the proofs stay on the software path
// and this file is held to it by test/aes_equiv_test.c, which runs both
// implementations over the same inputs and compares byte for byte.
#include "quic_aes_block.h"

#if defined(CH_TRANSPORT_QUIC) || defined(CH_SUITE_AES_GCM)
#ifdef CH_AES_HW

#include <stddef.h>
#include <string.h>

#include "ct.h"

#ifdef __ARM_FEATURE_AES
#include <arm_neon.h>
typedef uint8x16_t aes_state;
#elif defined(__AES__)
#include <wmmintrin.h>
typedef __m128i aes_state;
#else
#error                                                                                             \
    "AES=hw needs the AES instructions: compile with -march=armv8-a+crypto or -maes, or build AES=soft"
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
#ifdef __ARM_FEATURE_AES
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

void aes_expand_round_keys(const uint8_t key[AES_128_KEY],
                           uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK]) {
    // FIPS 197 §5.2, the same expansion quic_aes_soft.c writes, with the
    // instruction-backed SubWord above in place of the table lookup. The
    // two files agree byte for byte, which test/aes_equiv_test.c checks.
    uint8_t round_constant = 0x01;
    memcpy(round_keys, key, AES_128_KEY);
    uint8_t word[4];
    uint8_t substituted[4] = {0};
    for (size_t i = AES_128_KEY; i < (size_t)AES_ROUND_KEYS * AES_BLOCK; i += 4) {
        memcpy(word, &round_keys[i - 4], sizeof word);
        if (i % AES_128_KEY == 0) {
            sub_word(word, substituted);
            // RotWord, then the round constant on the first byte.
            word[0] = (uint8_t)(substituted[1] ^ round_constant);
            word[1] = substituted[2];
            word[2] = substituted[3];
            word[3] = substituted[0];
            round_constant = xtime(round_constant);
        }
        for (size_t j = 0; j < sizeof word; j++) {
            round_keys[i + j] = (uint8_t)(round_keys[i - AES_128_KEY + j] ^ word[j]);
        }
    }
    // Both temporaries hold bytes of the last round key. Under
    // -DCH_SUITE_AES_GCM that is a traffic key, and this is the one
    // implementation that build may take, so the wipe runs here and not in
    // quic_aes_soft.c. Two calls and two fixed sizes, so the wipe itself
    // reads nothing it was given.
    ct_wipe(word, sizeof word);
    ct_wipe(substituted, sizeof substituted);
}

#ifdef __ARM_FEATURE_AES
void aes_cipher_block(const uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK],
                      const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    // vaeseq_u8(s, k) is ShiftRows(SubBytes(s XOR k)) and vaesmcq_u8 is
    // MixColumns, so each pair below is one FIPS 197 §5.1 round with its
    // AddRoundKey taken from the front of the next instruction. Round
    // AES_128_ROUNDS drops MixColumns and its AddRoundKey is the
    // exclusive-or that follows.
    aes_state state = load_block(in);
    for (size_t round = 0; round < AES_128_ROUNDS - 1; round++) {
        state = vaeseq_u8(state, load_block(&round_keys[round * AES_BLOCK]));
        state = vaesmcq_u8(state);
    }
    state = vaeseq_u8(state, load_block(&round_keys[(size_t)(AES_128_ROUNDS - 1) * AES_BLOCK]));
    state = veorq_u8(state, load_block(&round_keys[(size_t)AES_128_ROUNDS * AES_BLOCK]));
    store_block(out, state);
    // state holds the block this call produced, which under
    // AEAD_AES_128_GCM is one block of keystream. out already holds it, so
    // the wipe removes the copy this frame would leave behind.
    ct_wipe(&state, sizeof state);
}
#else
void aes_cipher_block(const uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK],
                      const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    // _mm_aesenc_si128(s, k) is MixColumns(SubBytes(ShiftRows(s))) XOR k,
    // one whole FIPS 197 §5.1 round with its AddRoundKey at the end, and
    // _mm_aesenclast_si128 is the same without MixColumns. So the first
    // AddRoundKey is written out and the rounds follow it.
    aes_state state = load_block(in);
    state = _mm_xor_si128(state, load_block(round_keys));
    for (size_t round = 1; round < AES_128_ROUNDS; round++) {
        state = _mm_aesenc_si128(state, load_block(&round_keys[round * AES_BLOCK]));
    }
    state =
        _mm_aesenclast_si128(state, load_block(&round_keys[(size_t)AES_128_ROUNDS * AES_BLOCK]));
    store_block(out, state);
    // The arm above states why.
    ct_wipe(&state, sizeof state);
}
#endif

#endif // CH_AES_HW
#endif // CH_TRANSPORT_QUIC || CH_SUITE_AES_GCM
