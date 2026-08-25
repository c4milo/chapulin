#include "sha3.h"

#include "ct.h"

// Keccak is constant time by construction: fixed rotations, XORs, and
// AND-NOT over public loop indices, no secret-dependent branches or
// memory indices. Keep it that way. Lengths and positions are public;
// only the lane contents carry secrets.

// FIPS 202 §3.2.5: the round constants RC[0..23] for iota.
static const uint64_t RC[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

// FIPS 202 §3.2.2: the rho rotation offset of lane (x, y), indexed
// x + 5*y.
static const unsigned RHO[25] = {0,  1,  62, 28, 27, //
                                 36, 44, 6,  55, 20, //
                                 3,  10, 43, 25, 39, //
                                 41, 45, 15, 21, 8,  //
                                 18, 2,  61, 56, 14};

// FIPS 202 §B.2: the domain-separation bits, packed with the first pad
// bit into one byte. SHA-3 appends 01, SHAKE appends 1111.
#define SHA3_DOMAIN 0x06
#define SHAKE_DOMAIN 0x1f

// r may be 0 (lane (0,0) in rho); masking the right shift keeps 64 - r
// in range instead of branching on it.
static uint64_t rotate_left(uint64_t x, unsigned r) {
    return (x << r) | (x >> ((64 - r) & 63));
}

static void keccak_round(uint64_t a[25], uint64_t round_constant) {
    // theta (FIPS 202 §3.2.1): XOR the two neighboring column
    // parities into every lane.
    uint64_t c[5];
    for (int x = 0; x < 5; x++) {
        c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    }
    for (int x = 0; x < 5; x++) {
        uint64_t d = c[(x + 4) % 5] ^ rotate_left(c[(x + 1) % 5], 1);
        for (int y = 0; y < 25; y += 5) {
            a[y + x] ^= d;
        }
    }
    // rho and pi (§3.2.2, §3.2.3): rotate lane (x, y) by its offset and
    // move it to (y, 2x + 3y).
    uint64_t b[25];
    for (int x = 0; x < 5; x++) {
        for (int y = 0; y < 5; y++) {
            b[y + 5 * ((2 * x + 3 * y) % 5)] = rotate_left(a[x + 5 * y], RHO[x + 5 * y]);
        }
    }
    // chi (§3.2.4): the one nonlinear step.
    for (int y = 0; y < 25; y += 5) {
        for (int x = 0; x < 5; x++) {
            a[y + x] = b[y + x] ^ (~b[y + (x + 1) % 5] & b[y + (x + 2) % 5]);
        }
    }
    // iota (§3.2.5).
    a[0] ^= round_constant;
}

static void keccak_f1600(uint64_t a[25]) {
    for (int round = 0; round < 24; round++) {
        keccak_round(a, RC[round]);
    }
}

// Bytes map to lanes little-endian (FIPS 202 §3.1.2), emitted and read
// byte by byte so the host's endianness never enters. Both sponge
// directions finish the partly used block first and then work from a
// block boundary, the shape sha256_update has: the permutation count
// is bounded by whole blocks, and every byte loop after the first runs
// from offset zero. The CBMC harness depends on both — a permutation
// guarded per byte unrolls into one symbolic copy per byte, and a byte
// index offset by the write position makes every lane access symbolic.
static void absorb(uint64_t lane[25], size_t rate, size_t *pos, const uint8_t *in, size_t n) {
    size_t fill = *pos;
    if (fill > 0) {
        size_t take = rate - fill;
        if (take > n) {
            take = n;
        }
        for (size_t i = 0; i < take; i++) {
            lane[(fill + i) / 8] ^= (uint64_t)in[i] << (8 * ((fill + i) % 8));
        }
        fill += take;
        in += take;
        n -= take;
        if (fill == rate) {
            keccak_f1600(lane);
            fill = 0;
        }
    }
    while (n >= rate) {
        for (size_t i = 0; i < rate; i++) {
            lane[i / 8] ^= (uint64_t)in[i] << (8 * (i % 8));
        }
        keccak_f1600(lane);
        in += rate;
        n -= rate;
    }
    for (size_t i = 0; i < n; i++) {
        lane[i / 8] ^= (uint64_t)in[i] << (8 * (i % 8));
    }
    *pos = fill + n;
}

// Close the message: XOR the domain byte at the write position and the
// final pad bit into the block's last byte (FIPS 202 §B.2). When one
// byte remains the two XOR into the same byte, which is the standard's
// single-byte case.
static void pad_finish(uint64_t lane[25], size_t rate, size_t *pos, uint8_t domain) {
    lane[*pos / 8] ^= (uint64_t)domain << (8 * (*pos % 8));
    lane[(rate - 1) / 8] ^= (uint64_t)0x80 << (8 * ((rate - 1) % 8));
    keccak_f1600(lane);
    *pos = 0;
}

static void squeeze(uint64_t lane[25], size_t rate, size_t *pos, uint8_t *out, size_t n) {
    size_t drained = *pos;
    if (drained < rate) {
        size_t take = rate - drained;
        if (take > n) {
            take = n;
        }
        for (size_t i = 0; i < take; i++) {
            out[i] = (uint8_t)(lane[(drained + i) / 8] >> (8 * ((drained + i) % 8)));
        }
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
        for (size_t i = 0; i < take; i++) {
            out[i] = (uint8_t)(lane[i / 8] >> (8 * (i % 8)));
        }
        drained = take;
        out += take;
        n -= take;
    }
    *pos = drained;
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
