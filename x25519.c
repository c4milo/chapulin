#include "x25519.h"

#include "ct.h"

// Field element: 16 limbs of 16 bits, little-endian, radix 2^16, values
// mod 2^255-19. Limbs live in int64 so products and transient negatives
// from subtraction stay exact; carries re-normalize.
typedef int64_t fe[16];

static const fe F121665 = {0xdb41, 1};

// One carry pass. The 2^16 bias before the shift makes the floor shift
// round negative limbs correctly; the top limb's carry folds back to limb
// 0 times 38 (= 2*19, since 2^256 = 38 mod p).
static void carry(fe o) {
    for (int i = 0; i < 16; i++) {
        o[i] += (int64_t)1 << 16;
        int64_t c = o[i] >> 16;
        o[(size_t)((i + 1) * (i < 15))] += c - 1 + 37 * (c - 1) * (i == 15);
        // c * 2^16 as a multiply: c goes negative for negative limbs, and
        // left-shifting a negative value is UB that a compiler may exploit.
        o[i] -= c * ((int64_t)1 << 16);
    }
}

// Constant-time conditional swap: b is 1 or 0.
static void cswap(fe p, fe q, int64_t b) {
    int64_t mask = ~(b - 1);
    for (int i = 0; i < 16; i++) {
        int64_t t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void add(fe o, const fe a, const fe b) {
    for (int i = 0; i < 16; i++) {
        o[i] = a[i] + b[i];
    }
}

static void sub(fe o, const fe a, const fe b) {
    for (int i = 0; i < 16; i++) {
        o[i] = a[i] - b[i];
    }
}

static void mul(fe o, const fe a, const fe b) {
    int64_t t[31] = {0};
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            t[i + j] += a[i] * b[j];
        }
    }
    // 2^256 = 38 mod p folds the high half down.
    for (int i = 0; i < 15; i++) {
        t[i] += 38 * t[i + 16];
    }
    for (int i = 0; i < 16; i++) {
        o[i] = t[i];
    }
    carry(o);
    carry(o);
}

static void sqr(fe o, const fe a) {
    mul(o, a, a);
}

// a^(p-2) by square-and-multiply over the fixed exponent 2^255-21; the
// loop shape never depends on the value being inverted.
static void invert(fe o, const fe a) {
    fe c;
    for (int i = 0; i < 16; i++) {
        c[i] = a[i];
    }
    for (int i = 253; i >= 0; i--) {
        sqr(c, c);
        if (i != 2 && i != 4) {
            mul(c, c, a);
        }
    }
    for (int i = 0; i < 16; i++) {
        o[i] = c[i];
    }
}

static void unpack(fe o, const uint8_t n[X25519_LEN]) {
    for (size_t i = 0; i < 16; i++) {
        o[i] = (int64_t)n[2 * i] | ((int64_t)n[2 * i + 1] << 8);
    }
    // RFC 7748: the top bit of the u-coordinate is masked off.
    o[15] &= 0x7fff;
}

// Freeze to the canonical representative and serialize. Two conditional
// subtractions of p cover the maximum residue after three carry passes.
static void pack(uint8_t o[X25519_LEN], const fe n) {
    fe t;
    fe m;
    for (int i = 0; i < 16; i++) {
        t[i] = n[i];
    }
    carry(t);
    carry(t);
    carry(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int64_t borrow = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        cswap(t, m, 1 - borrow);
    }
    for (size_t i = 0; i < 16; i++) {
        o[2 * i] = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)((t[i] >> 8) & 0xff);
    }
}

static void ladder(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN],
                   const uint8_t point[X25519_LEN]) {
    uint8_t z[X25519_LEN];
    fe x;
    fe a;
    fe b;
    fe c;
    fe d;
    fe e;
    fe f;
    for (int i = 0; i < X25519_LEN; i++) {
        z[i] = scalar[i];
    }
    // RFC 7748 clamp.
    z[0] &= 248;
    z[31] = (z[31] & 127) | 64;

    unpack(x, point);
    for (int i = 0; i < 16; i++) {
        b[i] = x[i];
        a[i] = c[i] = d[i] = 0;
    }
    a[0] = d[0] = 1;

    for (int i = 254; i >= 0; i--) {
        int64_t r = (z[i >> 3] >> (i & 7)) & 1;
        cswap(a, b, r);
        cswap(c, d, r);
        add(e, a, c);
        sub(a, a, c);
        add(c, b, d);
        sub(b, b, d);
        sqr(d, e);
        sqr(f, a);
        mul(a, c, a);
        mul(c, b, e);
        add(e, a, c);
        sub(a, a, c);
        sqr(b, a);
        sub(c, d, f);
        mul(a, c, F121665);
        add(a, a, d);
        mul(c, c, a);
        mul(a, d, f);
        mul(d, b, x);
        sqr(b, e);
        cswap(a, b, r);
        cswap(c, d, r);
    }
    invert(c, c);
    mul(a, a, c);
    pack(out, a);

    ct_wipe(z, sizeof z);
    ct_wipe(a, sizeof(fe));
    ct_wipe(b, sizeof(fe));
    ct_wipe(c, sizeof(fe));
    ct_wipe(d, sizeof(fe));
    ct_wipe(e, sizeof(fe));
    ct_wipe(f, sizeof(fe));
}

int x25519(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN],
           const uint8_t point[X25519_LEN]) {
    static const uint8_t zeros[X25519_LEN] = {0};
    ladder(out, scalar, point);
    return !ct_memeq(out, zeros, X25519_LEN);
}

void x25519_base(uint8_t out[X25519_LEN], const uint8_t scalar[X25519_LEN]) {
    static const uint8_t nine[X25519_LEN] = {9};
    ladder(out, scalar, nine);
}
