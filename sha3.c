#include "sha3.h"

#include "ct.h"
#include "keccak_round_constants.h"

// Keccak is constant time by construction: fixed rotations, XORs, and
// AND-NOT, with no secret-dependent branches or memory indices. Keep it
// that way. Lengths and positions are public; only the lane contents
// carry secrets.

// sha3_hw.c compiles this file once more for an arm64 host object that
// clang compiles, under second names and with Keccak-f[1600] on the SHA-3
// instructions (docs/decisions.md 99). That copy defines CH_SHA3_HW_COPY
// and supplies the two functions the sponge calls for the permutation,
// keccak_f1600 and absorb_whole_blocks, so the text between each #ifndef
// below and its #endif is this file's alone.
#ifndef CH_SHA3_HW_COPY

// r is 1 to 63 at every call below.
static uint64_t rotate_left(uint64_t x, unsigned r) {
    return (x << r) | (x >> (64 - r));
}

// One round of Keccak-f[1600] (FIPS 202 §3.2), written out lane by lane.
// The standard states the five steps as loops over a lane's column x and
// row y, with lane (x, y) at index x + 5y. Written out, they are:
//
//   theta (§3.2.1): c0..c4 are the five column parities, and d0..d4 what
//     theta XORs into every lane of a column: d[x] = c[x - 1] ^
//     rotate_left(c[x + 1], 1), the indices modulo 5. The 25 lines after
//     them XOR each lane's d into it, in place.
//   rho and pi (§3.2.2, §3.2.3): rho rotates lane (x, y) by a fixed
//     offset and pi moves it to (y, 2x + 3y). The 25 lines that set
//     b0..b24 are that rule solved for the source: b[X + 5Y] is lane
//     (x, X), for x = (X + 3Y) mod 5, rotated by that lane's offset.
//     Lane (0, 0) has offset 0, so b0 has no rotation.
//   chi (§3.2.4): a[x + 5y] = b[x + 5y] ^ (~b[x + 1 + 5y] & b[x + 2 + 5y]),
//     with x + 1 and x + 2 modulo 5. It is the one nonlinear step.
//   iota (§3.2.5): the round constant into lane 0.
//
// Every lane is read into a b before chi writes any lane, so the round
// works in place on one array.
//
// Why written out. The loops need a table of offsets, a rotation by a
// variable count and five `% 5`, and a compiler that does not unroll
// them, which gcc at -O2 does not, runs them at several times the cost
// (docs/decisions.md 98). proof/sha3_reference.h holds the standard's
// loops, and proof/sha3_round_harness.c proves this round equal to them
// for every state and every round constant.
//
// Why theta is its own 25 lines. Each rotation below takes a lane, never
// an expression such as a[6] ^ d1. CBMC kept a value computed in a
// call's argument in every formula, so with the XOR inside the call the
// sha3 harness carried every bit of every permutation: 21 million
// clauses where it now carries 11 (docs/proofs.md). A compiler removes
// the 25 stores: chi overwrites each lane before anything else reads it.
static void keccak_round(uint64_t a[25], uint64_t round_constant) {
    uint64_t c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
    uint64_t c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
    uint64_t c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
    uint64_t c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
    uint64_t c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
    uint64_t d0 = c4 ^ rotate_left(c1, 1);
    uint64_t d1 = c0 ^ rotate_left(c2, 1);
    uint64_t d2 = c1 ^ rotate_left(c3, 1);
    uint64_t d3 = c2 ^ rotate_left(c4, 1);
    uint64_t d4 = c3 ^ rotate_left(c0, 1);

    a[0] ^= d0;
    a[5] ^= d0;
    a[10] ^= d0;
    a[15] ^= d0;
    a[20] ^= d0;
    a[1] ^= d1;
    a[6] ^= d1;
    a[11] ^= d1;
    a[16] ^= d1;
    a[21] ^= d1;
    a[2] ^= d2;
    a[7] ^= d2;
    a[12] ^= d2;
    a[17] ^= d2;
    a[22] ^= d2;
    a[3] ^= d3;
    a[8] ^= d3;
    a[13] ^= d3;
    a[18] ^= d3;
    a[23] ^= d3;
    a[4] ^= d4;
    a[9] ^= d4;
    a[14] ^= d4;
    a[19] ^= d4;
    a[24] ^= d4;

    uint64_t b0 = a[0];
    uint64_t b1 = rotate_left(a[6], 44);
    uint64_t b2 = rotate_left(a[12], 43);
    uint64_t b3 = rotate_left(a[18], 21);
    uint64_t b4 = rotate_left(a[24], 14);

    uint64_t b5 = rotate_left(a[3], 28);
    uint64_t b6 = rotate_left(a[9], 20);
    uint64_t b7 = rotate_left(a[10], 3);
    uint64_t b8 = rotate_left(a[16], 45);
    uint64_t b9 = rotate_left(a[22], 61);

    uint64_t b10 = rotate_left(a[1], 1);
    uint64_t b11 = rotate_left(a[7], 6);
    uint64_t b12 = rotate_left(a[13], 25);
    uint64_t b13 = rotate_left(a[19], 8);
    uint64_t b14 = rotate_left(a[20], 18);

    uint64_t b15 = rotate_left(a[4], 27);
    uint64_t b16 = rotate_left(a[5], 36);
    uint64_t b17 = rotate_left(a[11], 10);
    uint64_t b18 = rotate_left(a[17], 15);
    uint64_t b19 = rotate_left(a[23], 56);

    uint64_t b20 = rotate_left(a[2], 62);
    uint64_t b21 = rotate_left(a[8], 55);
    uint64_t b22 = rotate_left(a[14], 39);
    uint64_t b23 = rotate_left(a[15], 41);
    uint64_t b24 = rotate_left(a[21], 2);

    a[0] = b0 ^ (~b1 & b2);
    a[1] = b1 ^ (~b2 & b3);
    a[2] = b2 ^ (~b3 & b4);
    a[3] = b3 ^ (~b4 & b0);
    a[4] = b4 ^ (~b0 & b1);
    a[5] = b5 ^ (~b6 & b7);
    a[6] = b6 ^ (~b7 & b8);
    a[7] = b7 ^ (~b8 & b9);
    a[8] = b8 ^ (~b9 & b5);
    a[9] = b9 ^ (~b5 & b6);
    a[10] = b10 ^ (~b11 & b12);
    a[11] = b11 ^ (~b12 & b13);
    a[12] = b12 ^ (~b13 & b14);
    a[13] = b13 ^ (~b14 & b10);
    a[14] = b14 ^ (~b10 & b11);
    a[15] = b15 ^ (~b16 & b17);
    a[16] = b16 ^ (~b17 & b18);
    a[17] = b17 ^ (~b18 & b19);
    a[18] = b18 ^ (~b19 & b15);
    a[19] = b19 ^ (~b15 & b16);
    a[20] = b20 ^ (~b21 & b22);
    a[21] = b21 ^ (~b22 & b23);
    a[22] = b22 ^ (~b23 & b24);
    a[23] = b23 ^ (~b24 & b20);
    a[24] = b24 ^ (~b20 & b21);

    a[0] ^= round_constant;
}

static void keccak_f1600(uint64_t a[25]) {
    for (int round = 0; round < 24; round++) {
        keccak_round(a, RC[round]);
    }
}

#endif // CH_SHA3_HW_COPY

// Bytes map to lanes little-endian (FIPS 202 §3.1.2): byte i of a block
// is byte i % 8 of lane i / 8, counted from the lane's low end. Every
// function below names a lane's bytes one by one, so the host's
// endianness never enters.
static void xor_byte(uint64_t lane[25], size_t at, uint8_t byte) {
    lane[at / 8] ^= (uint64_t)byte << (8 * (at % 8));
}

static uint8_t byte_at(const uint64_t lane[25], size_t at) {
    return (uint8_t)(lane[at / 8] >> (8 * (at % 8)));
}

// Eight bytes as one lane, and one lane as eight bytes. A compiler makes
// one load or one store of the eight where the target allows it. Both
// name each byte: written as a loop over the eight, the store stayed a
// loop under gcc 13 at -O2, one byte stored per iteration.
static uint64_t lane_from_bytes(const uint8_t b[8]) {
    return (uint64_t)b[0] | ((uint64_t)b[1] << 8) | ((uint64_t)b[2] << 16) |
           ((uint64_t)b[3] << 24) | ((uint64_t)b[4] << 32) | ((uint64_t)b[5] << 40) |
           ((uint64_t)b[6] << 48) | ((uint64_t)b[7] << 56);
}

static void lane_to_bytes(uint8_t b[8], uint64_t lane) {
    b[0] = (uint8_t)lane;
    b[1] = (uint8_t)(lane >> 8);
    b[2] = (uint8_t)(lane >> 16);
    b[3] = (uint8_t)(lane >> 24);
    b[4] = (uint8_t)(lane >> 32);
    b[5] = (uint8_t)(lane >> 40);
    b[6] = (uint8_t)(lane >> 48);
    b[7] = (uint8_t)(lane >> 56);
}

// XORs the n bytes at in into the block from byte position pos on, for
// pos + n at most the rate: one byte at a time up to a lane's first
// byte, then eight bytes at a time, then the bytes that do not fill a
// lane. The first and the last step move at most seven bytes each.
static void block_xor(uint64_t lane[25], size_t pos, const uint8_t *in, size_t n) {
    size_t i = 0;
    for (; i < n && (pos + i) % 8 != 0; i++) {
        xor_byte(lane, pos + i, in[i]);
    }
    for (; n - i >= 8; i += 8) {
        lane[(pos + i) / 8] ^= lane_from_bytes(in + i);
    }
    for (; i < n; i++) {
        xor_byte(lane, pos + i, in[i]);
    }
}

// Writes n bytes of the block at out, from byte position pos on, in the
// same three steps. The eight-byte step names the lane before the call
// that writes it out, for the reason keccak_round gives for theta.
static void block_bytes(uint8_t *out, const uint64_t lane[25], size_t pos, size_t n) {
    size_t i = 0;
    for (; i < n && (pos + i) % 8 != 0; i++) {
        out[i] = byte_at(lane, pos + i);
    }
    for (; n - i >= 8; i += 8) {
        uint64_t value = lane[(pos + i) / 8];
        lane_to_bytes(out + i, value);
    }
    for (; i < n; i++) {
        out[i] = byte_at(lane, pos + i);
    }
}

#ifndef CH_SHA3_HW_COPY

// XORs each whole block of the *n bytes at *in into the lanes and runs the
// permutation after it, and moves *in and *n past the blocks it took,
// which leaves fewer than one block.
static void absorb_whole_blocks(uint64_t lane[25], size_t rate, const uint8_t **in, size_t *n) {
    while (*n >= rate) {
        block_xor(lane, 0, *in, rate);
        keccak_f1600(lane);
        *in += rate;
        *n -= rate;
    }
}

#endif // CH_SHA3_HW_COPY

// Both sponge directions finish the partly used block first and then
// work from a block's first byte, the shape sha256_update has, so the
// permutation runs once per whole block and never once per byte. The
// CBMC harnesses depend on that count: a permutation guarded per byte
// unrolls into one symbolic copy per byte.
static void absorb(uint64_t lane[25], size_t rate, size_t *pos, const uint8_t *in, size_t n) {
    size_t fill = *pos;
    if (fill > 0) {
        size_t take = rate - fill;
        if (take > n) {
            take = n;
        }
        block_xor(lane, fill, in, take);
        fill += take;
        in += take;
        n -= take;
        if (fill == rate) {
            keccak_f1600(lane);
            fill = 0;
        }
    }
    absorb_whole_blocks(lane, rate, &in, &n);
    // Bytes are left only when the block is empty: a block the first
    // step did not fill took every byte there was.
    block_xor(lane, 0, in, n);
    *pos = fill + n;
}

static void squeeze(uint64_t lane[25], size_t rate, size_t *pos, uint8_t *out, size_t n) {
    size_t drained = *pos;
    if (drained < rate) {
        size_t take = rate - drained;
        if (take > n) {
            take = n;
        }
        block_bytes(out, lane, drained, take);
        drained += take;
        out += take;
        n -= take;
    }
    while (n > 0) {
        keccak_f1600(lane);
        size_t take = rate;
        if (take > n) {
            take = n;
        }
        block_bytes(out, lane, 0, take);
        drained = take;
        out += take;
        n -= take;
    }
    *pos = drained;
}

// FIPS 202 §B.2: the domain-separation bits, packed with the first pad
// bit into one byte. SHA-3 appends 01, SHAKE appends 1111.
#define SHA3_DOMAIN 0x06
#define SHAKE_DOMAIN 0x1f

// Close the message: XOR the domain byte at the write position and the
// final pad bit into the block's last byte (FIPS 202 §B.2). When one
// byte remains the two XOR into the same byte, which is the standard's
// single-byte case.
static void pad_finish(uint64_t lane[25], size_t rate, size_t *pos, uint8_t domain) {
    xor_byte(lane, *pos, domain);
    xor_byte(lane, rate - 1, 0x80);
    keccak_f1600(lane);
    *pos = 0;
}

static void keccak(size_t rate, uint8_t domain, const uint8_t *in, size_t n, uint8_t *out,
                   size_t out_len) {
    uint64_t lane[25] = {0};
    size_t pos = 0;
    absorb(lane, rate, &pos, in, n);
    pad_finish(lane, rate, &pos, domain);
    squeeze(lane, rate, &pos, out, out_len);
    // The state absorbed the whole message, and the caller cannot reach
    // this frame; hkdf.c wipes its internal sha256 context for the same
    // reason.
    ct_wipe(lane, sizeof lane);
}

void sha3_256(const uint8_t *in, size_t n, uint8_t out[SHA3_256_LEN]) {
    keccak(SHA3_256_RATE, SHA3_DOMAIN, in, n, out, SHA3_256_LEN);
}

void sha3_512(const uint8_t *in, size_t n, uint8_t out[SHA3_512_LEN]) {
    keccak(SHA3_512_RATE, SHA3_DOMAIN, in, n, out, SHA3_512_LEN);
}

static void shake_init(shake *s, size_t rate) {
    for (int i = 0; i < 25; i++) {
        s->lane[i] = 0;
    }
    s->rate = rate;
    s->pos = 0;
    s->squeezing = 0;
}

void shake128_init(shake *s) {
    shake_init(s, SHAKE128_RATE);
}

void shake256_init(shake *s) {
    shake_init(s, SHAKE256_RATE);
}

void shake_absorb(shake *s, const uint8_t *in, size_t n) {
    absorb(s->lane, s->rate, &s->pos, in, n);
}

void shake_squeeze(shake *s, uint8_t *out, size_t n) {
    if (!s->squeezing) {
        pad_finish(s->lane, s->rate, &s->pos, SHAKE_DOMAIN);
        s->squeezing = 1;
    }
    squeeze(s->lane, s->rate, &s->pos, out, n);
}
