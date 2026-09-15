// NIST P-384 field and scalar arithmetic. Variable time on purpose —
// every input is public (see p384.h). Multiplication reduces
// word-by-word Montgomery-style (CIOS), with one constant set per
// modulus so the field prime p and the group order n share every
// routine; inverses are Fermat powers. Clarity over speed: this runs
// once per connection.
#include "p384_field.h"

#include <string.h>

// SEC 2 curve constants; r2/m0inv derived from them (2^768 mod m and
// -m^-1 mod 2^32). test/gen_p384_constants.py prints these limbs after
// checking every parameter against `openssl ecparam -name secp384r1
// -param_enc explicit -text -noout`.
const p384_modulus p384_modp = {
    {0xffffffff, 0x00000000, 0x00000000, 0xffffffff, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff,
     0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff},
    {0x00000001, 0xfffffffe, 0x00000000, 0x00000002, 0x00000000, 0xfffffffe, 0x00000000, 0x00000002,
     0x00000001, 0x00000000, 0x00000000, 0x00000000},
    0x00000001,
};

const p384_modulus p384_modn = {
    {0xccc52973, 0xecec196a, 0x48b0a77a, 0x581a0db2, 0xf4372ddf, 0xc7634d81, 0xffffffff, 0xffffffff,
     0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff},
    {0x19b409a9, 0x2d319b24, 0xdf1aa419, 0xff3d81e5, 0xfcb82947, 0xbc3e483a, 0x4aab1cc5, 0xd40d4917,
     0x28266895, 0x3fb05b7a, 0x2b39bf21, 0x0c84ee01},
    0xe88fdc45,
};

int p384_is_zero(const uint32_t a[P384_LIMBS]) {
    uint32_t v = 0;
    for (int i = 0; i < P384_LIMBS; i++) {
        v |= a[i];
    }
    return v == 0;
}

int p384_compare(const uint32_t a[P384_LIMBS], const uint32_t b[P384_LIMBS]) {
    for (int i = P384_LIMBS - 1; i >= 0; i--) {
        if (a[i] != b[i]) {
            return a[i] < b[i] ? -1 : 1;
        }
    }
    return 0;
}

// 48 big-endian bytes -> 12 little-endian limbs, byte by byte.
void p384_from_bytes(uint32_t o[P384_LIMBS], const uint8_t b[P384_LEN]) {
    for (int i = 0; i < P384_LIMBS; i++) {
        o[i] = (uint32_t)b[P384_LEN - 1 - 4 * i] | ((uint32_t)b[P384_LEN - 2 - 4 * i] << 8) |
               ((uint32_t)b[P384_LEN - 3 - 4 * i] << 16) |
               ((uint32_t)b[P384_LEN - 4 - 4 * i] << 24);
    }
}

uint32_t p384_add_raw(uint32_t o[P384_LIMBS], const uint32_t a[P384_LIMBS],
                      const uint32_t b[P384_LIMBS]) {
    uint64_t c = 0;
    for (int i = 0; i < P384_LIMBS; i++) {
        c += (uint64_t)a[i] + b[i];
        o[i] = (uint32_t)c;
        c >>= 32;
    }
    return (uint32_t)c;
}

uint32_t p384_sub_raw(uint32_t o[P384_LIMBS], const uint32_t a[P384_LIMBS],
                      const uint32_t b[P384_LIMBS]) {
    uint64_t borrow = 0;
    for (int i = 0; i < P384_LIMBS; i++) {
        uint64_t v = (uint64_t)a[i] - b[i] - borrow;
        o[i] = (uint32_t)v;
        borrow = (v >> 32) & 1;
    }
    return (uint32_t)borrow;
}

// Inputs below m; one conditional subtract covers the sum (< 2m).
void p384_mod_add(uint32_t o[P384_LIMBS], const uint32_t a[P384_LIMBS],
                  const uint32_t b[P384_LIMBS], const p384_modulus *mod) {
    uint32_t c = p384_add_raw(o, a, b);
    if (c || p384_compare(o, mod->m) >= 0) {
        (void)p384_sub_raw(o, o, mod->m);
    }
}

void p384_mod_sub(uint32_t o[P384_LIMBS], const uint32_t a[P384_LIMBS],
                  const uint32_t b[P384_LIMBS], const p384_modulus *mod) {
    if (p384_sub_raw(o, a, b)) {
        (void)p384_add_raw(o, o, mod->m);
    }
}

// Montgomery product o = a*b / 2^384 mod m (CIOS, Koç et al.). Inputs
// below m, result below m; o may alias a or b. Each round adds one limb
// of a into t, then adds a multiple of m to zero t's low limb and
// shifts down one limb.
void p384_mont_mul(uint32_t o[P384_LIMBS], const uint32_t a[P384_LIMBS],
                   const uint32_t b[P384_LIMBS], const p384_modulus *mod) {
    uint32_t t[P384_LIMBS + 2] = {0};
    for (int i = 0; i < P384_LIMBS; i++) {
        uint64_t c = 0;
        for (int j = 0; j < P384_LIMBS; j++) {
            uint64_t v = (uint64_t)a[i] * b[j] + t[j] + c;
            t[j] = (uint32_t)v;
            c = v >> 32;
        }
        uint64_t v = (uint64_t)t[P384_LIMBS] + c;
        t[P384_LIMBS] = (uint32_t)v;
        t[P384_LIMBS + 1] = (uint32_t)(v >> 32);

        uint32_t u = t[0] * mod->m0inv;
        c = ((uint64_t)u * mod->m[0] + t[0]) >> 32;
        for (int j = 1; j < P384_LIMBS; j++) {
            v = (uint64_t)u * mod->m[j] + t[j] + c;
            t[j - 1] = (uint32_t)v;
            c = v >> 32;
        }
        v = (uint64_t)t[P384_LIMBS] + c;
        t[P384_LIMBS - 1] = (uint32_t)v;
        t[P384_LIMBS] = t[P384_LIMBS + 1] + (uint32_t)(v >> 32);
        t[P384_LIMBS + 1] = 0;
    }
    // t < 2m with at most one bit in t[P384_LIMBS]; the subtraction's
    // borrow cancels that bit exactly, so the low limbs are the answer.
    if (t[P384_LIMBS] || p384_compare(t, mod->m) >= 0) {
        (void)p384_sub_raw(o, t, mod->m);
    } else {
        memcpy(o, t, P384_LIMBS * sizeof(uint32_t));
    }
}

// Plain product mod m: into the Montgomery domain and back in one extra
// multiply (a*b/R, then *R^2/R).
void p384_mod_mul(uint32_t o[P384_LIMBS], const uint32_t a[P384_LIMBS],
                  const uint32_t b[P384_LIMBS], const p384_modulus *mod) {
    uint32_t t[P384_LIMBS];
    p384_mont_mul(t, a, b, mod);
    p384_mont_mul(o, t, mod->r2, mod);
}

// o = a^(m-2) mod m: Fermat inverse, square-and-multiply in the
// Montgomery domain. The exponent is a public constant, so the
// bit-dependent multiply leaks nothing.
void p384_mod_inverse(uint32_t o[P384_LIMBS], const uint32_t a[P384_LIMBS],
                      const p384_modulus *mod) {
    static const uint32_t one[P384_LIMBS] = {1};
    uint32_t e[P384_LIMBS];
    uint32_t a_mont[P384_LIMBS];
    uint32_t acc[P384_LIMBS];
    memcpy(e, mod->m, sizeof e);
    e[0] -= 2;                              // both moduli end well above 2: no borrow
    p384_mont_mul(a_mont, a, mod->r2, mod); // a*R
    p384_mont_mul(acc, one, mod->r2, mod);  // 1*R
    for (int i = 383; i >= 0; i--) {
        p384_mont_mul(acc, acc, acc, mod);
        if ((e[i / 32] >> (i % 32)) & 1) {
            p384_mont_mul(acc, acc, a_mont, mod);
        }
    }
    p384_mont_mul(o, acc, one, mod); // strip the R factor
}
