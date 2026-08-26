// Z_q arithmetic, NTT, sampling, and byte packing for ML-KEM-768.
// The arithmetic is the signed-Montgomery form: coefficients are int16,
// products reduce through a multiply and a shift, never a divide (the
// KyberSlash lesson, enforced as INV-23). Zetas below are the FIPS 203
// twiddle factors already scaled into the Montgomery domain.
#include "mlkem_poly.h"

#include "ct.h"
#include "sha3.h"

// zetas[k] = zeta^bitreverse7(k) * 2^16 mod q, reduced to (-q/2, q/2].
// zeta = 17 is the primitive 256th root fixed by FIPS 203. The first 64
// drive the NTT butterflies; entries 64..127 are the basemul twiddles.
static const int16_t MLK_ZETAS[128] = {
    -1044, -758,  -359,  -1517, 1493,  1422,  287,   202,   -171,  622,   1577,  182,   962,
    -1202, -1474, 1468,  573,   -1325, 264,   383,   -829,  1458,  -1602, -130,  -681,  1017,
    732,   608,   -1542, 411,   -205,  -1571, 1223,  652,   -552,  1015,  -1293, 1491,  -282,
    -1544, 516,   -8,    -320,  -666,  -1618, -1162, 126,   1469,  -853,  -90,   -271,  830,
    107,   -1421, -247,  -951,  -398,  961,   -1508, -725,  448,   -1065, 677,   -1275, -1103,
    430,   555,   843,   -1251, 871,   1550,  105,   422,   587,   177,   -235,  -291,  -460,
    1574,  1653,  -246,  778,   1159,  -147,  -777,  1483,  -602,  1119,  -1590, 644,   -872,
    349,   418,   329,   -156,  -75,   817,   1097,  603,   610,   1322,  -1285, -1465, 384,
    -1215, -136,  1218,  -1335, -874,  220,   -1187, -1659, -1185, -1530, -1278, 794,   -1510,
    -854,  -870,  478,   -108,  -308,  996,   991,   958,   -1460, 1522,  1628};

// a * R^-1 mod q, signed. -3327 = q^-1 mod 2^16.
static int16_t mlk_montgomery_reduce(int32_t a) {
    int16_t t = (int16_t)((int16_t)a * (int16_t)-3327);
    return (int16_t)((a - (int32_t)t * MLKEM_Q) >> 16);
}

// Centers a into (-q/2, q/2]. 20159 = round(2^26 / q); the +2^25 rounds.
static int16_t mlk_barrett_reduce(int16_t a) {
    int16_t t = (int16_t)(((int32_t)20159 * a + (1 << 25)) >> 26);
    return (int16_t)(a - (int32_t)t * MLKEM_Q);
}

static int16_t mlk_fqmul(int16_t a, int16_t b) {
    return mlk_montgomery_reduce((int32_t)a * b);
}

// a in (-q, q) -> its canonical representative in [0, q). Branchless: the
// arithmetic shift spreads the sign bit to a mask of q for negatives.
static uint16_t mlk_freeze(int16_t a) {
    return (uint16_t)(int16_t)(a + ((a >> 15) & MLKEM_Q));
}

// round(2^d * x / q) mod 2^d for x in [0, q), as a multiply-shift with no
// divide. 1290168 = ceil(2^32 / q); the +1664 supplies the rounding, and
// the rounding is exact only with the ceiling, not the floor.
static uint16_t mlk_compress(uint16_t x, unsigned d) {
    uint64_t t = (((uint64_t)x << d) + 1664U) * 1290168U;
    return (uint16_t)((t >> 32) & ((1U << d) - 1U));
}

// round(y * q / 2^d) as (y*q + 2^(d-1)) >> d. Exact, no divide.
static int16_t mlk_decompress(uint16_t y, unsigned d) {
    return (int16_t)(((uint32_t)y * MLKEM_Q + (1U << (d - 1))) >> d);
}

void mlk_poly_reduce(mlk_poly *p) {
    for (unsigned i = 0; i < 256; i++) {
        p->coeffs[i] = mlk_barrett_reduce(p->coeffs[i]);
    }
}

void mlk_poly_tomont(mlk_poly *p) {
    // Multiply by R = 2^16: montgomery_reduce(x * R^2) = x * R. 1353 = 2^32 mod q.
    for (unsigned i = 0; i < 256; i++) {
        p->coeffs[i] = mlk_montgomery_reduce((int32_t)p->coeffs[i] * 1353);
    }
}

void mlk_poly_add(mlk_poly *r, const mlk_poly *a, const mlk_poly *b) {
    for (unsigned i = 0; i < 256; i++) {
        r->coeffs[i] = (int16_t)(a->coeffs[i] + b->coeffs[i]);
    }
}

void mlk_poly_sub(mlk_poly *r, const mlk_poly *a, const mlk_poly *b) {
    for (unsigned i = 0; i < 256; i++) {
        r->coeffs[i] = (int16_t)(a->coeffs[i] - b->coeffs[i]);
    }
}

// Cooley-Tukey NTT, seven layers, halving the butterfly span each layer.
// Reduces at the end so the output serializes canonically.
void mlk_poly_ntt(mlk_poly *p) {
    int16_t *r = p->coeffs;
    unsigned k = 1;
    for (unsigned len = 128; len >= 2; len >>= 1) {
        for (unsigned start = 0; start < 256; start += 2 * len) {
            int16_t zeta = MLK_ZETAS[k];
            k++;
            for (unsigned j = start; j < start + len; j++) {
                int16_t t = mlk_fqmul(zeta, r[j + len]);
                r[j + len] = (int16_t)(r[j] - t);
                r[j] = (int16_t)(r[j] + t);
            }
        }
    }
    mlk_poly_reduce(p);
}

// Gentleman-Sande inverse NTT, split at the len 16/32 boundary into two
// halves so each is one CBMC formula: as a single formula the transform
// returns no verdict in 900 seconds, while each half proves with every
// check on. The split is proof structure only — running the halves in
// order is the reference loop, and the twiddle index k continues where
// the low half stopped.
//
// mlk_invntt_low: the len 2..16 butterfly layers, twiddles k = 127..8.
static void mlk_invntt_low(int16_t *r) {
    unsigned k = 127;
    for (unsigned len = 2; len <= 16; len <<= 1) {
        for (unsigned start = 0; start < 256; start += 2 * len) {
            int16_t zeta = MLK_ZETAS[k];
            k--;
            for (unsigned j = start; j < start + len; j++) {
                int16_t t = r[j];
                r[j] = mlk_barrett_reduce((int16_t)(t + r[j + len]));
                r[j + len] = (int16_t)(r[j + len] - t);
                r[j + len] = mlk_fqmul(zeta, r[j + len]);
            }
        }
    }
}

// mlk_invntt_high: the len 32..128 layers, twiddles k = 7..1, then the
// final pass, which multiplies every coefficient by 1441 =
// 2^32 / 128 mod q — the 1/128 of seven layers and the Montgomery
// factor in one multiply.
static void mlk_invntt_high(int16_t *r) {
    unsigned k = 7;
    for (unsigned len = 32; len <= 128; len <<= 1) {
        for (unsigned start = 0; start < 256; start += 2 * len) {
            int16_t zeta = MLK_ZETAS[k];
            k--;
            for (unsigned j = start; j < start + len; j++) {
                int16_t t = r[j];
                r[j] = mlk_barrett_reduce((int16_t)(t + r[j + len]));
                r[j + len] = (int16_t)(r[j + len] - t);
                r[j + len] = mlk_fqmul(zeta, r[j + len]);
            }
        }
    }
    for (unsigned j = 0; j < 256; j++) {
        r[j] = mlk_fqmul(r[j], 1441);
    }
}

void mlk_poly_invntt(mlk_poly *p) {
    mlk_invntt_low(p->coeffs);
    mlk_invntt_high(p->coeffs);
}

// One degree-1 product in Z_q[X]/(X^2 - zeta), the shape MultiplyNTTs
// uses for each coefficient pair.
static void mlk_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta) {
    r[0] = mlk_fqmul(mlk_fqmul(a[1], b[1]), zeta);
    r[0] = (int16_t)(r[0] + mlk_fqmul(a[0], b[0]));
    r[1] = mlk_fqmul(a[0], b[1]);
    r[1] = (int16_t)(r[1] + mlk_fqmul(a[1], b[0]));
}

void mlk_poly_basemul(mlk_poly *r, const mlk_poly *a, const mlk_poly *b) {
    for (size_t i = 0; i < 64; i++) {
        int16_t zeta = MLK_ZETAS[64 + i];
        mlk_basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i], zeta);
        mlk_basemul(&r->coeffs[4 * i + 2], &a->coeffs[4 * i + 2], &b->coeffs[4 * i + 2],
                    (int16_t)-zeta);
    }
}

void mlk_poly_tobytes(uint8_t out[MLK_POLY_BYTES], const mlk_poly *p) {
    for (size_t i = 0; i < 128; i++) {
        uint16_t t0 = mlk_freeze(p->coeffs[2 * i]);
        uint16_t t1 = mlk_freeze(p->coeffs[2 * i + 1]);
        out[3 * i + 0] = (uint8_t)t0;
        out[3 * i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        out[3 * i + 2] = (uint8_t)(t1 >> 4);
    }
}

void mlk_poly_frombytes(mlk_poly *p, const uint8_t in[MLK_POLY_BYTES]) {
    for (size_t i = 0; i < 128; i++) {
        uint16_t lo = (uint16_t)(in[3 * i] | ((uint16_t)in[3 * i + 1] << 8));
        uint16_t hi = (uint16_t)((in[3 * i + 1] >> 4) | ((uint16_t)in[3 * i + 2] << 4));
        p->coeffs[2 * i] = (int16_t)(lo & 0xfff);
        p->coeffs[2 * i + 1] = (int16_t)(hi & 0xfff);
    }
}

void mlk_polyvec_compress(uint8_t out[MLK_POLYVEC_COMP_BYTES], const mlk_polyvec *v) {
    unsigned o = 0;
    for (unsigned n = 0; n < 3; n++) {
        const mlk_poly *p = &v->vec[n];
        for (size_t j = 0; j < 64; j++) {
            uint16_t t0 = mlk_compress(mlk_freeze(p->coeffs[4 * j]), 10);
            uint16_t t1 = mlk_compress(mlk_freeze(p->coeffs[4 * j + 1]), 10);
            uint16_t t2 = mlk_compress(mlk_freeze(p->coeffs[4 * j + 2]), 10);
            uint16_t t3 = mlk_compress(mlk_freeze(p->coeffs[4 * j + 3]), 10);
            out[o + 0] = (uint8_t)t0;
            out[o + 1] = (uint8_t)((t0 >> 8) | (t1 << 2));
            out[o + 2] = (uint8_t)((t1 >> 6) | (t2 << 4));
            out[o + 3] = (uint8_t)((t2 >> 4) | (t3 << 6));
            out[o + 4] = (uint8_t)(t3 >> 2);
            o += 5;
        }
    }
}

void mlk_polyvec_decompress(mlk_polyvec *v, const uint8_t in[MLK_POLYVEC_COMP_BYTES]) {
    unsigned o = 0;
    for (unsigned n = 0; n < 3; n++) {
        mlk_poly *p = &v->vec[n];
        for (size_t j = 0; j < 64; j++) {
            const uint8_t *a = &in[o];
            uint16_t t0 = (uint16_t)(a[0] | ((uint16_t)a[1] << 8));
            uint16_t t1 = (uint16_t)((a[1] >> 2) | ((uint16_t)a[2] << 6));
            uint16_t t2 = (uint16_t)((a[2] >> 4) | ((uint16_t)a[3] << 4));
            uint16_t t3 = (uint16_t)((a[3] >> 6) | ((uint16_t)a[4] << 2));
            p->coeffs[4 * j + 0] = mlk_decompress((uint16_t)(t0 & 0x3ff), 10);
            p->coeffs[4 * j + 1] = mlk_decompress((uint16_t)(t1 & 0x3ff), 10);
            p->coeffs[4 * j + 2] = mlk_decompress((uint16_t)(t2 & 0x3ff), 10);
            p->coeffs[4 * j + 3] = mlk_decompress((uint16_t)(t3 & 0x3ff), 10);
            o += 5;
        }
    }
}

void mlk_poly_compress(uint8_t out[MLK_POLY_COMP_BYTES], const mlk_poly *p) {
    for (size_t i = 0; i < 32; i++) {
        uint16_t t[8];
        for (size_t j = 0; j < 8; j++) {
            t[j] = mlk_compress(mlk_freeze(p->coeffs[8 * i + j]), 4);
        }
        out[4 * i + 0] = (uint8_t)(t[0] | (t[1] << 4));
        out[4 * i + 1] = (uint8_t)(t[2] | (t[3] << 4));
        out[4 * i + 2] = (uint8_t)(t[4] | (t[5] << 4));
        out[4 * i + 3] = (uint8_t)(t[6] | (t[7] << 4));
    }
}

void mlk_poly_decompress(mlk_poly *p, const uint8_t in[MLK_POLY_COMP_BYTES]) {
    for (size_t i = 0; i < 128; i++) {
        p->coeffs[2 * i] = mlk_decompress((uint16_t)(in[i] & 0x0f), 4);
        p->coeffs[2 * i + 1] = mlk_decompress((uint16_t)(in[i] >> 4), 4);
    }
}

void mlk_poly_frommsg(mlk_poly *p, const uint8_t msg[32]) {
    for (size_t i = 0; i < 32; i++) {
        for (size_t j = 0; j < 8; j++) {
            int16_t mask = (int16_t)(-(int16_t)((msg[i] >> j) & 1));
            p->coeffs[8 * i + j] = (int16_t)(mask & 1665); // (q+1)/2
        }
    }
}

// Constant time: the decrypted message is secret, so every coefficient
// goes through the branchless freeze and compress, never a comparison.
void mlk_poly_tomsg(uint8_t msg[32], const mlk_poly *p) {
    for (size_t i = 0; i < 32; i++) {
        uint8_t b = 0;
        for (size_t j = 0; j < 8; j++) {
            uint16_t bit = mlk_compress(mlk_freeze(p->coeffs[8 * i + j]), 1);
            b = (uint8_t)(b | (bit << j));
        }
        msg[i] = b;
    }
}

// Rejection sampling reads three XOF bytes per two candidate coefficients
// and keeps each only if it is below q. The XOF stream derives from the
// public seed rho, so this data-dependent control flow leaks nothing
// secret; matrix A is public by construction.
//
// The read is capped at MLK_SAMPLE_GROUPS three-byte groups (1536
// bytes). FIPS 203 reads an unbounded stream; 704 bytes already puts
// the probability of needing more below 2^-128 (C2SP/CCTV's bound), so
// no reachable seed hits the cap — the unluckysample vector, built to
// need over 575 bytes, passes. The cap is what lets the CBMC harness
// unwind this loop with unwinding assertions on. If the cap is ever
// hit the remaining coefficients keep the value the caller's poly held.
void mlk_sample_ntt(mlk_poly *p, const uint8_t seed[32], uint8_t x0, uint8_t x1) {
    shake s;
    const uint8_t idx[2] = {x0, x1};
    uint8_t buf[3];
    shake128_init(&s);
    shake_absorb(&s, seed, 32);
    shake_absorb(&s, idx, 2);
    unsigned j = 0;
    for (unsigned group = 0; group < MLK_SAMPLE_GROUPS && j < 256; group++) {
        shake_squeeze(&s, buf, 3);
        uint16_t d1 = (uint16_t)(buf[0] | ((uint16_t)(buf[1] & 0x0f) << 8));
        uint16_t d2 = (uint16_t)((buf[1] >> 4) | ((uint16_t)buf[2] << 4));
        if (d1 < MLKEM_Q) {
            p->coeffs[j] = (int16_t)d1;
            j++;
        }
        if (d2 < MLKEM_Q && j < 256) {
            p->coeffs[j] = (int16_t)d2;
            j++;
        }
    }
}

// Centered binomial noise, eta=2: each coefficient is (popcount of two
// secret bits) minus (popcount of two more). Reads the PRF stream at
// fixed indices, so it is constant time; the buffer and sponge are wiped.
void mlk_sample_cbd(mlk_poly *p, const uint8_t seed[32], uint8_t nonce) {
    shake s;
    uint8_t buf[MLK_CBD_BYTES];
    shake256_init(&s);
    shake_absorb(&s, seed, 32);
    shake_absorb(&s, &nonce, 1);
    shake_squeeze(&s, buf, MLK_CBD_BYTES);
    for (size_t i = 0; i < 32; i++) {
        uint32_t t = (uint32_t)buf[4 * i] | ((uint32_t)buf[4 * i + 1] << 8) |
                     ((uint32_t)buf[4 * i + 2] << 16) | ((uint32_t)buf[4 * i + 3] << 24);
        uint32_t d = (t & 0x55555555U) + ((t >> 1) & 0x55555555U);
        for (size_t j = 0; j < 8; j++) {
            int16_t a = (int16_t)((d >> (4 * j)) & 0x3);
            int16_t b = (int16_t)((d >> (4 * j + 2)) & 0x3);
            p->coeffs[8 * i + j] = (int16_t)(a - b);
        }
    }
    ct_wipe(buf, sizeof buf);
    ct_wipe(&s, sizeof s);
}
