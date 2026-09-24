// AES=soft, the default: the AES-128 key expansion and forward cipher of
// FIPS 197 in C, with the S-box as a 256-byte table.
// quic_aes_block.h states both contracts; this file implements them and
// nothing else.
//
// The table is indexed with cipher state, so this code does not run in
// constant time against its key. aes_expand_round_keys substitutes the
// key's own bytes before a single block runs, and sub_bytes substitutes
// the state once per round. That is the trade INV-26 in
// docs/invariants.md states and bounds: the only keys that reach it are
// the ones RFC 9001 fixes for QUIC Initial packets (§5.2), their header
// protection (§5.1, §5.4.3) and the Retry integrity tag (§5.8), and
// every one of those is public. No key from the TLS key schedule reaches
// it. An AES=hw build has no table and no such trade, which is what
// docs/decisions.md entry 6 says a secret-key AES suite would need.
//
// This file holds no wipe, where quic_aes_hw.c wipes its round-key word
// and its cipher state. The bound above is why: a -DCH_SUITE_AES_GCM
// build is the only one whose key is secret, ct.h refuses that build
// unless it also takes AES=hw, so no key this file expands is ever worth
// wiping and the stores would cost a device something for nothing.
//
// Under -DCH_AES_256_TEST it also holds AES-256, as the software
// reference test/aes_equiv_test.c and proof/quic_aes256_harness.c hold
// quic_aes_hw.c's AES-256 to. Only tests and proofs define that macro. A
// library object takes AES-256 only for TLS_AES_256_GCM_SHA384, whose key
// is secret, and so only with AES=hw.
#include "quic_aes_block.h"

#if defined(CH_TRANSPORT_QUIC) || defined(CH_SUITE_AES_GCM)
#ifndef CH_AES_HW
#ifndef CH_AES_EXTERN

// The fence the paragraph above states, written in this file so that it
// holds for a tree that compiles this source with its own build system and
// never reads ct.h's refusal. A suite build hands AES a traffic key, and
// this S-box is indexed with the key.
#ifdef CH_SUITE_AES_GCM
#error "CH_SUITE_AES_GCM never compiles AES=soft: its S-box is indexed with the key (INV-26)"
#endif

#include <stddef.h>
#include <string.h>

// The substitution table of FIPS 197 §5.1.1, Figure 7: SBOX[b] is the
// S-box applied to the byte b. The key expansion of §5.2 reads it too.
static const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

// One multiplication by x in GF(2^8), FIPS 197 §4.2. The left shift
// drops bit 7, and the field polynomial x^8+x^4+x^3+x+1 puts 0x1b back
// exactly when bit 7 was set. The mask is arithmetic rather than a
// branch because it is shorter to read, not because the byte is secret.
static uint8_t xtime(uint8_t b) {
    uint8_t high_set = (uint8_t)(0U - (unsigned)(b >> 7)); // 0xff when bit 7 was set, else 0
    return (uint8_t)(((unsigned)b << 1) ^ (0x1bU & high_set));
}

// FIPS 197 §5.1.4, AddRoundKey: the state is exclusive-ored with one
// round key.
static void add_round_key(uint8_t state[AES_BLOCK], const uint8_t round_key[AES_BLOCK]) {
    for (size_t i = 0; i < AES_BLOCK; i++) {
        state[i] = (uint8_t)(state[i] ^ round_key[i]);
    }
}

// FIPS 197 §5.1.1, SubBytes: every byte of the state goes through the
// S-box.
static void sub_bytes(uint8_t state[AES_BLOCK]) {
    for (size_t i = 0; i < AES_BLOCK; i++) {
        state[i] = SBOX[state[i]];
    }
}

// FIPS 197 §5.1.2, ShiftRows: row r of the state moves left by r
// columns. Byte i of the state is row i % 4 of column i / 4 (§3.4), and
// the state has 4 columns, so the column index wraps under a mask
// rather than a division.
static void shift_rows(uint8_t state[AES_BLOCK]) {
    uint8_t shifted[AES_BLOCK];
    for (size_t row = 0; row < 4; row++) {
        for (size_t col = 0; col < 4; col++) {
            shifted[row + 4 * col] = state[row + 4 * ((col + row) & 3U)];
        }
    }
    memcpy(state, shifted, AES_BLOCK);
}

// FIPS 197 §5.1.3, MixColumns: each column is multiplied by the fixed
// polynomial. Written as the equal form that needs one xtime per byte:
// the new byte is the old byte, exclusive-ored with the sum of the whole
// column, exclusive-ored with twice the sum of that byte and the next.
static void mix_columns(uint8_t state[AES_BLOCK]) {
    for (size_t col = 0; col < 4; col++) {
        uint8_t *column = &state[4 * col];
        uint8_t sum = (uint8_t)(column[0] ^ column[1] ^ column[2] ^ column[3]);
        uint8_t first = column[0];
        column[0] = (uint8_t)(column[0] ^ sum ^ xtime((uint8_t)(column[0] ^ column[1])));
        column[1] = (uint8_t)(column[1] ^ sum ^ xtime((uint8_t)(column[1] ^ column[2])));
        column[2] = (uint8_t)(column[2] ^ sum ^ xtime((uint8_t)(column[2] ^ column[3])));
        column[3] = (uint8_t)(column[3] ^ sum ^ xtime((uint8_t)(column[3] ^ first)));
    }
}

void aes_expand_round_keys(const uint8_t key[AES_128_KEY],
                           uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK]) {
    // FIPS 197 §5.2, Key Expansion, for Nk = 4: the 16 key bytes are the
    // first round key, and each later 4-byte word is the word 16 bytes
    // back exclusive-ored with the word before it. Every fourth word
    // takes RotWord, SubWord and the round constant first.
    uint8_t round_constant = 0x01;
    memcpy(round_keys, key, AES_128_KEY);
    for (size_t i = AES_128_KEY; i < (size_t)AES_ROUND_KEYS * AES_BLOCK; i += 4) {
        uint8_t word[4];
        memcpy(word, &round_keys[i - 4], sizeof word);
        if (i % AES_128_KEY == 0) {
            uint8_t first = word[0];
            word[0] = (uint8_t)(SBOX[word[1]] ^ round_constant);
            word[1] = SBOX[word[2]];
            word[2] = SBOX[word[3]];
            word[3] = SBOX[first];
            round_constant = xtime(round_constant);
        }
        for (size_t j = 0; j < sizeof word; j++) {
            round_keys[i + j] = (uint8_t)(round_keys[i - AES_128_KEY + j] ^ word[j]);
        }
    }
}

void aes_cipher_block(const uint8_t round_keys[AES_ROUND_KEYS * AES_BLOCK],
                      const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    // FIPS 197 §5.1, the forward cipher CIPH_K: one AddRoundKey, nine
    // full rounds, and a last round without MixColumns. The input is
    // copied into a local state first, so a caller that passes the same
    // buffer as in and out gets the right answer.
    uint8_t state[AES_BLOCK];
    memcpy(state, in, AES_BLOCK);
    add_round_key(state, round_keys);
    for (size_t round = 1; round < AES_128_ROUNDS; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &round_keys[round * AES_BLOCK]);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &round_keys[(size_t)AES_128_ROUNDS * AES_BLOCK]);
    memcpy(out, state, AES_BLOCK);
}

#ifdef CH_AES_256
// The software AES-256 reference, which only a test binary or a proof
// harness compiles (-DCH_AES_256_TEST, quic_aes.h). Written apart
// from the AES-128 pair above rather than folded into it, so that pair
// and the proof and the branch counts that measure it stay as they were.

// FIPS 197 §5.1.1's SubWord applied in place: the S-box on each of 4
// bytes.
static void sub_word(uint8_t word[4]) {
    for (size_t j = 0; j < 4; j++) {
        word[j] = SBOX[word[j]];
    }
}

void aes_expand_round_keys_256(const uint8_t key[AES_256_KEY],
                               uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK]) {
    // FIPS 197 §5.2, Key Expansion, for Nk = 8: the 32 key bytes are the
    // first two round keys, and each later word is the word 32 bytes back
    // exclusive-ored with the word before it. Every eighth word takes
    // RotWord, SubWord and the round constant first, and the fourth word
    // after it takes SubWord alone.
    uint8_t round_constant = 0x01;
    memcpy(round_keys, key, AES_256_KEY);
    for (size_t i = AES_256_KEY; i < (size_t)AES_256_ROUND_KEYS * AES_BLOCK; i += 4) {
        uint8_t word[4];
        memcpy(word, &round_keys[i - 4], sizeof word);
        if (i % AES_256_KEY == 0) {
            uint8_t first = word[0];
            word[0] = word[1];
            word[1] = word[2];
            word[2] = word[3];
            word[3] = first;
            sub_word(word);
            word[0] = (uint8_t)(word[0] ^ round_constant);
            round_constant = xtime(round_constant);
        } else if (i % AES_256_KEY == AES_BLOCK) {
            sub_word(word);
        }
        for (size_t j = 0; j < sizeof word; j++) {
            round_keys[i + j] = (uint8_t)(round_keys[i - AES_256_KEY + j] ^ word[j]);
        }
    }
}

void aes_cipher_block_256(const uint8_t round_keys[AES_256_ROUND_KEYS * AES_BLOCK],
                          const uint8_t in[AES_BLOCK], uint8_t out[AES_BLOCK]) {
    // FIPS 197 §5.1 for Nr = 14: one AddRoundKey, thirteen full rounds,
    // and a last round without MixColumns. The input is copied into a
    // local state first, so in == out works.
    uint8_t state[AES_BLOCK];
    memcpy(state, in, AES_BLOCK);
    add_round_key(state, round_keys);
    for (size_t round = 1; round < AES_256_ROUNDS; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &round_keys[round * AES_BLOCK]);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &round_keys[(size_t)AES_256_ROUNDS * AES_BLOCK]);
    memcpy(out, state, AES_BLOCK);
}
#endif // CH_AES_256

#endif // CH_AES_EXTERN
#endif // CH_AES_HW
#endif // CH_TRANSPORT_QUIC || CH_SUITE_AES_GCM
