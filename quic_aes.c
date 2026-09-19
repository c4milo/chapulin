// The AES-128 forward cipher of FIPS 197 and the two constructors of the
// one key type it takes. quic_aes.h states every contract; this file
// implements them and nothing else.
//
// The S-box below is a lookup table indexed with cipher state, so this
// code does not run in constant time against its key. That is the trade
// INV-26 in docs/invariants.md states and bounds: the only keys that
// reach this file are the Initial keys, which anyone who sees a
// Destination Connection ID can derive (RFC 9001 §5.2), the header
// protection key derived from the same secret (§5.1), and the Retry key
// the RFC prints (§5.8). No key from the TLS key schedule reaches it.
#include "quic_aes.h"

#ifdef CH_TRANSPORT_QUIC

#include <string.h>

#include "hkdf.h"
#include "quic_aes_key.h"

// RFC 9001 §5.2's printed salt, the input every Initial secret starts
// from (rfc9001.txt:1051-1055, rfc9001.txt:1066).
static const uint8_t INITIAL_SALT[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34,
                                         0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                                         0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};

// RFC 9001 §5.8's printed Retry integrity tag key, 0xbe0c690b9f66575a1d766b54e368c84e
// (rfc9001.txt:1499-1500).
static const uint8_t RETRY_KEY[AES_128_KEY] = {0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
                                               0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e};

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

// FIPS 197 §5.2, Key Expansion, for Nk = 4: the 16 key bytes are the
// first round key, and each later 4-byte word is the word 16 bytes back
// exclusive-ored with the word before it. Every fourth word takes
// RotWord, SubWord and the round constant first.
static void expand_key(const uint8_t key[AES_128_KEY], aes_key_schedule *schedule) {
    uint8_t round_constant = 0x01;
    memcpy(schedule->round_keys, key, AES_128_KEY);
    for (size_t i = AES_128_KEY; i < sizeof schedule->round_keys; i += 4) {
        uint8_t word[4];
        memcpy(word, &schedule->round_keys[i - 4], sizeof word);
        if (i % AES_128_KEY == 0) {
            uint8_t first = word[0];
            word[0] = (uint8_t)(SBOX[word[1]] ^ round_constant);
            word[1] = SBOX[word[2]];
            word[2] = SBOX[word[3]];
            word[3] = SBOX[first];
            round_constant = xtime(round_constant);
        }
        for (size_t j = 0; j < sizeof word; j++) {
            schedule->round_keys[i + j] =
                (uint8_t)(schedule->round_keys[i - AES_128_KEY + j] ^ word[j]);
        }
    }
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

// FIPS 197 §5.1, the forward cipher CIPH_K: one AddRoundKey, nine full
// rounds, and a last round without MixColumns. The input is copied into
// a local state first, so a caller that passes the same buffer as in and
// out gets the right answer.
static void cipher(const aes_key_schedule *schedule, const uint8_t in[AES_BLOCK],
                   uint8_t out[AES_BLOCK]) {
    uint8_t state[AES_BLOCK];
    memcpy(state, in, AES_BLOCK);
    add_round_key(state, schedule->round_keys);
    for (size_t round = 1; round < AES_128_ROUNDS; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &schedule->round_keys[round * AES_BLOCK]);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &schedule->round_keys[(size_t)AES_128_ROUNDS * AES_BLOCK]);
    memcpy(out, state, AES_BLOCK);
}

int aes_public_key_initial(aes_public_key *k, const uint8_t *dcid, size_t dcid_len,
                           uint8_t direction) {
    if (dcid_len > CH_QUIC_DCID_MAX) {
        return CH_EINVAL;
    }
    if (direction != CH_KEY_READ && direction != CH_KEY_WRITE) {
        return CH_EINVAL;
    }
    // RFC 9001 §5.2: the salt and the Destination Connection ID extract
    // one secret, and one label per direction expands it
    // (rfc9001.txt:1057-1061). This client writes what "client in"
    // protects and reads what "server in" protects.
    uint8_t initial_secret[SHA256_LEN];
    hkdf_extract(INITIAL_SALT, sizeof INITIAL_SALT, dcid, dcid_len, initial_secret);
    const char *label = direction == CH_KEY_WRITE ? "client in" : "server in";
    // RFC 9001 §5.2 names this one client_initial_secret or
    // server_initial_secret, one per direction.
    uint8_t direction_secret[SHA256_LEN];
    hkdf_expand_label(initial_secret, label, NULL, 0, direction_secret, sizeof direction_secret);
    // RFC 9001 §5.1: three labels over that secret, each with a
    // zero-length context (rfc9001.txt:1029-1032).
    uint8_t key[AES_128_KEY];
    hkdf_expand_label(direction_secret, "quic key", NULL, 0, key, sizeof key);
    expand_key(key, &k->key);
    hkdf_expand_label(direction_secret, "quic iv", NULL, 0, k->iv, sizeof k->iv);
    hkdf_expand_label(direction_secret, "quic hp", NULL, 0, key, sizeof key);
    expand_key(key, &k->hp);
    // No wipe: every byte above is public. RFC 9001 §5 says so of the
    // Initial keys themselves (rfc9001.txt:999-1001), and INV-26 admits
    // no other key here. ct_wipe would tell a reader these bytes are
    // secret, which is the one thing this file may never imply.
    return CH_OK;
}

void aes_public_key_retry(aes_public_key *k) {
    expand_key(RETRY_KEY, &k->key);
    // RFC 9001 §5.8 prints the nonce the caller passes to gcm_seal, and
    // a Retry packet carries no header protection, so both fields stay
    // zero rather than holding a key this call did not derive.
    memset(k->iv, 0, sizeof k->iv);
    memset(&k->hp, 0, sizeof k->hp);
}

void aes_encrypt_block(const aes_public_key *k, const uint8_t in[AES_BLOCK],
                       uint8_t out[AES_BLOCK]) {
    cipher(&k->key, in, out);
}

void aes_encrypt_block_hp(const aes_public_key *k, const uint8_t sample[AES_BLOCK],
                          uint8_t out[AES_BLOCK]) {
    cipher(&k->hp, sample, out);
}

#endif // CH_TRANSPORT_QUIC
