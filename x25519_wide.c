// X25519=wide: the field arithmetic mod p = 2^255-19 and the Montgomery
// ladder of RFC 7748 section 5, in radix 2^51. An element is five limbs
// of 51 bits in uint64_t, and every product is one ct_mul128, the
// 64x64->128 multiply ct.h defines only for this build. It runs the same
// ladder step as x25519.c's 16-limb field, in the same order, on a tenth of
// the multiplies: 25 products per field multiply instead of 256.
//
// The limb bounds are INV-34 in docs/invariants.md, and every one of them
// is a claim a proof checks:
//
//   unpack        every limb in [0, 2^51).
//   mul, sqr      operands' limbs under 2^54. Each product is under
//                 38 * 2^108, which is under 2^114; each column sums to
//                 under 77 * 2^108, which is under 2^115; and every carry
//                 between columns is under 2^64. The result's limbs are in
//                 [0, 2^51), except limb 1 in [0, 2^51 + 2^13).
//   mul_a24       operand limbs under 2^54; the result as for mul.
//   add           two results of mul, so each limb under 2^53.
//   sub           a + 2p - b for two results of mul: b's limbs never pass
//                 2p's, so nothing wraps, and each limb is under 2^53.
//
// So every operand the ladder hands mul or sqr is under 2^53, half the 2^54
// their proofs take. proof/x25519_wide_*_harness.c prove each line with
// --unsigned-overflow-check on, because unsigned arithmetic wraps silently
// in C and the default checks would see no wrap at all. Under the multiply
// contract the ladder proofs use, limb 1 of a result is under 2^51 + 2^20
// rather than 2^51 + 2^13; proof/x25519_wide_stubs.h says why.
//
// Constant time: no branch and no memory index depends on a limb or on a
// scalar bit. cswap selects with a mask, the loops count public numbers,
// and the one instruction whose timing the C cannot state is the multiply,
// which is what CH_NATIVE_MUL128 asserts (ct.h).
#include "x25519_wide.h"

#ifdef CH_X25519_WIDE

#include <stddef.h>

#include "ct.h"

// A field element: value = f[0] + f[1] 2^51 + f[2] 2^102 + f[3] 2^153 +
// f[4] 2^204, taken mod p. A limb may exceed 51 bits between operations;
// the table above says by how much.
typedef uint64_t fe[5];

#define LIMB_BITS 51
#define LIMB_MASK ((UINT64_C(1) << LIMB_BITS) - 1)

// a24 = (486662 - 2) / 4, the constant RFC 7748's ladder multiplies by.
#define A24 UINT64_C(121665)

// 2p, limb by limb: 2^52 - 38 at the bottom, 2^52 - 2 above it.
#define TWO_P_0 UINT64_C(0xFFFFFFFFFFFDA)
#define TWO_P_1_4 UINT64_C(0xFFFFFFFFFFFFE)

// Five column sums to five limbs. Each column keeps its low 51 bits and
// passes the rest to the next; what passes out of the top column is worth 19
// at the bottom, because 2^255 = 19 mod p, and the last carry from limb 0
// goes to limb 1 and stops there. The carries stay 128 bits wide, so no bit
// of a sum is dropped: the only narrowings are of values masked to 51 bits
// and of r0's carry, which is under 2^31 whatever the sums are.
static void carry_columns(fe o, ct_u128 t0, ct_u128 t1, ct_u128 t2, ct_u128 t3, ct_u128 t4) {
    t1 += t0 >> LIMB_BITS;
    t2 += t1 >> LIMB_BITS;
    t3 += t2 >> LIMB_BITS;
    t4 += t3 >> LIMB_BITS;
    ct_u128 r0 = (t0 & LIMB_MASK) + (t4 >> LIMB_BITS) * 19;
    o[0] = (uint64_t)(r0 & LIMB_MASK);
    o[1] = (uint64_t)(t1 & LIMB_MASK) + (uint64_t)(r0 >> LIMB_BITS);
    o[2] = (uint64_t)(t2 & LIMB_MASK);
    o[3] = (uint64_t)(t3 & LIMB_MASK);
    o[4] = (uint64_t)(t4 & LIMB_MASK);
}

// o = a * b. Column k collects the products whose limb indices sum to k, and
// the ones that sum to k + 5 come in times 19. Every limb of a and b is read
// before o is written, so o may be a or b.
static void mul(fe o, const fe a, const fe b) {
    uint64_t b1_19 = b[1] * 19;
    uint64_t b2_19 = b[2] * 19;
    uint64_t b3_19 = b[3] * 19;
    uint64_t b4_19 = b[4] * 19;
    ct_u128 t0 = ct_mul128(a[0], b[0]) + ct_mul128(a[1], b4_19) + ct_mul128(a[2], b3_19) +
                 ct_mul128(a[3], b2_19) + ct_mul128(a[4], b1_19);
    ct_u128 t1 = ct_mul128(a[0], b[1]) + ct_mul128(a[1], b[0]) + ct_mul128(a[2], b4_19) +
                 ct_mul128(a[3], b3_19) + ct_mul128(a[4], b2_19);
    ct_u128 t2 = ct_mul128(a[0], b[2]) + ct_mul128(a[1], b[1]) + ct_mul128(a[2], b[0]) +
                 ct_mul128(a[3], b4_19) + ct_mul128(a[4], b3_19);
    ct_u128 t3 = ct_mul128(a[0], b[3]) + ct_mul128(a[1], b[2]) + ct_mul128(a[2], b[1]) +
                 ct_mul128(a[3], b[0]) + ct_mul128(a[4], b4_19);
    ct_u128 t4 = ct_mul128(a[0], b[4]) + ct_mul128(a[1], b[3]) + ct_mul128(a[2], b[2]) +
                 ct_mul128(a[3], b[1]) + ct_mul128(a[4], b[0]);
    carry_columns(o, t0, t1, t2, t3, t4);
}

// o = a * a: mul's columns with each pair of distinct limbs taken once and
// doubled, so 15 products instead of 25. The operands are ordered so the
// first is always under 2^55 and the second under 38 * 2^54, the domain
// proof/x25519_wide_stubs.h states for ct_mul128.
static void sqr(fe o, const fe a) {
    uint64_t a0_2 = a[0] * 2;
    uint64_t a1_2 = a[1] * 2;
    uint64_t a2_2 = a[2] * 2;
    uint64_t a3_19 = a[3] * 19;
    uint64_t a3_38 = a[3] * 38;
    uint64_t a4_19 = a[4] * 19;
    ct_u128 t0 = ct_mul128(a[0], a[0]) + ct_mul128(a1_2, a4_19) + ct_mul128(a2_2, a3_19);
    ct_u128 t1 = ct_mul128(a[1], a0_2) + ct_mul128(a2_2, a4_19) + ct_mul128(a[3], a3_19);
    ct_u128 t2 = ct_mul128(a[2], a0_2) + ct_mul128(a[1], a[1]) + ct_mul128(a[4], a3_38);
    ct_u128 t3 = ct_mul128(a[3], a0_2) + ct_mul128(a[2], a1_2) + ct_mul128(a[4], a4_19);
    ct_u128 t4 = ct_mul128(a[4], a0_2) + ct_mul128(a[3], a1_2) + ct_mul128(a[2], a[2]);
    carry_columns(o, t0, t1, t2, t3, t4);
}

// o = a * a24.
static void mul_a24(fe o, const fe a) {
    carry_columns(o, ct_mul128(a[0], A24), ct_mul128(a[1], A24), ct_mul128(a[2], A24),
                  ct_mul128(a[3], A24), ct_mul128(a[4], A24));
}

static void add(fe o, const fe a, const fe b) {
    for (size_t i = 0; i < 5; i++) {
        o[i] = a[i] + b[i];
    }
}

// o = a + 2p - b, which is a - b mod p with every limb kept non-negative.
// It needs each limb of b at or under 2p's, which every result of mul is.
static void sub(fe o, const fe a, const fe b) {
    o[0] = a[0] + TWO_P_0 - b[0];
    for (size_t i = 1; i < 5; i++) {
        o[i] = a[i] + TWO_P_1_4 - b[i];
    }
}

// Swaps p and q when bit is 1 and leaves them when it is 0, without a
// branch. The mask is the bit moved to the top and spread down by an
// arithmetic shift, the form x25519.c's cswap takes for the reason its
// comment gives: gcc rewrites `x & -bit` as a multiply by the bit.
static void cswap(fe p, fe q, uint64_t bit) {
    uint64_t mask = (uint64_t)((int64_t)(bit << 63) >> 63);
    for (size_t i = 0; i < 5; i++) {
        uint64_t t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

// o = a^(2^n): n squarings in a row. n is a constant at every call.
static void sqr_times(fe o, const fe a, int n) {
    sqr(o, a);
    for (int i = 1; i < n; i++) {
        sqr(o, o);
    }
}

// o = z^(p-2) = z^(2^255 - 21), the inverse of z, by a fixed chain of 254
// squarings and 11 multiplies. Each name says which power of z it holds:
// z2_5_0 is z^(2^5 - 2^0), and so on. The chain is the same for every z.
static void invert(fe o, const fe z) {
    fe z2;
    fe z9;
    fe z11;
    fe z2_5_0;
    fe z2_10_0;
    fe z2_20_0;
    fe z2_50_0;
    fe z2_100_0;
    fe t;
    sqr(z2, z);                // z^2
    sqr_times(t, z2, 2);       // z^8
    mul(z9, t, z);             // z^9
    mul(z11, z9, z2);          // z^11
    sqr(t, z11);               // z^22
    mul(z2_5_0, t, z9);        // z^(2^5 - 1)
    sqr_times(t, z2_5_0, 5);   // z^(2^10 - 2^5)
    mul(z2_10_0, t, z2_5_0);   // z^(2^10 - 1)
    sqr_times(t, z2_10_0, 10); // z^(2^20 - 2^10)
    mul(z2_20_0, t, z2_10_0);  // z^(2^20 - 1)
    sqr_times(t, z2_20_0, 20); // z^(2^40 - 2^20)
    mul(t, t, z2_20_0);        // z^(2^40 - 1)
    sqr_times(t, t, 10);       // z^(2^50 - 2^10)
    mul(z2_50_0, t, z2_10_0);  // z^(2^50 - 1)
    sqr_times(t, z2_50_0, 50); // z^(2^100 - 2^50)
    mul(z2_100_0, t, z2_50_0); // z^(2^100 - 1)
    sqr_times(t, z2_100_0, 100);
    mul(t, t, z2_100_0); // z^(2^200 - 1)
    sqr_times(t, t, 50);
    mul(t, t, z2_50_0); // z^(2^250 - 1)
    sqr_times(t, t, 5); // z^(2^255 - 2^5)
    mul(o, t, z11);     // z^(2^255 - 21)
    ct_wipe(z2, sizeof z2);
    ct_wipe(z9, sizeof z9);
    ct_wipe(z11, sizeof z11);
    ct_wipe(z2_5_0, sizeof z2_5_0);
    ct_wipe(z2_10_0, sizeof z2_10_0);
    ct_wipe(z2_20_0, sizeof z2_20_0);
    ct_wipe(z2_50_0, sizeof z2_50_0);
    ct_wipe(z2_100_0, sizeof z2_100_0);
    ct_wipe(t, sizeof t);
}

// Eight bytes, least significant first, whatever the host's byte order.
static uint64_t load_le64(const uint8_t b[8]) {
    uint64_t v = 0;
    for (size_t i = 8; i > 0; i--) {
        v = (v << 8) | b[i - 1];
    }
    return v;
}

static void store_le64(uint8_t b[8], uint64_t v) {
    for (size_t i = 0; i < 8; i++) {
        b[i] = (uint8_t)(v >> (8 * i));
    }
}

// The u-coordinate's 255 low bits into five limbs. RFC 7748 masks the top
// bit off. A value at or above p is kept as it is: mul reduces it like any
// other.
static void unpack(fe o, const uint8_t n[X25519_LEN]) {
    uint64_t w0 = load_le64(n);
    uint64_t w1 = load_le64(n + 8);
    uint64_t w2 = load_le64(n + 16);
    uint64_t w3 = load_le64(n + 24) & ~(UINT64_C(1) << 63);
    o[0] = w0 & LIMB_MASK;
    o[1] = ((w0 >> 51) | (w1 << 13)) & LIMB_MASK;
    o[2] = ((w1 >> 38) | (w2 << 26)) & LIMB_MASK;
    o[3] = ((w2 >> 25) | (w3 << 39)) & LIMB_MASK;
    o[4] = w3 >> 12;
}

// One pass of carries from each limb into the next, the top one coming in
// at the bottom times 19. Two passes leave every limb under 2^51 for any
// limbs under 2^63, which covers every value the ladder hands pack.
static void carry_limbs(uint64_t t[5]) {
    t[1] += t[0] >> LIMB_BITS;
    t[0] &= LIMB_MASK;
    t[2] += t[1] >> LIMB_BITS;
    t[1] &= LIMB_MASK;
    t[3] += t[2] >> LIMB_BITS;
    t[2] &= LIMB_MASK;
    t[4] += t[3] >> LIMB_BITS;
    t[3] &= LIMB_MASK;
    t[0] += (t[4] >> LIMB_BITS) * 19;
    t[4] &= LIMB_MASK;
}

// The canonical representative, below p, as 32 little-endian bytes. After
// two carry passes the value v is under 2^255 = p + 19, so it needs at most
// one subtraction of p. q is 1 exactly when v + 19 reaches 2^255, which is
// when v >= p; adding 19q and dropping bit 255 subtracts qp. q is computed,
// never branched on.
static void pack(uint8_t o[X25519_LEN], const fe n) {
    uint64_t t[5];
    for (size_t i = 0; i < 5; i++) {
        t[i] = n[i];
    }
    carry_limbs(t);
    carry_limbs(t);
    uint64_t q = (t[0] + 19) >> LIMB_BITS;
    q = (t[1] + q) >> LIMB_BITS;
    q = (t[2] + q) >> LIMB_BITS;
    q = (t[3] + q) >> LIMB_BITS;
    q = (t[4] + q) >> LIMB_BITS;
    t[0] += 19 * q;
    t[1] += t[0] >> LIMB_BITS;
    t[0] &= LIMB_MASK;
    t[2] += t[1] >> LIMB_BITS;
    t[1] &= LIMB_MASK;
    t[3] += t[2] >> LIMB_BITS;
    t[2] &= LIMB_MASK;
    t[4] += t[3] >> LIMB_BITS;
    t[3] &= LIMB_MASK;
    t[4] &= LIMB_MASK;
    store_le64(o, t[0] | (t[1] << 51));
    store_le64(o + 8, (t[1] >> 13) | (t[2] << 38));
    store_le64(o + 16, (t[2] >> 26) | (t[3] << 25));
    store_le64(o + 24, (t[3] >> 39) | (t[4] << 12));
    ct_wipe(t, sizeof t);
}

// One ladder step, x25519.c's step() over this field: the same operations in
// the same order, with mul_a24 where that file multiplies by the constant
// element. A function of its own so proof/x25519_wide_step_harness.c can run
// one step and prove it keeps every limb inside INV-34's bounds; the loop in
// x25519_wide_ladder() is the induction over it.
static void step(fe a, fe b, fe c, fe d, fe e, fe f, const fe x, uint64_t r) {
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
    mul_a24(a, c);
    add(a, a, d);
    mul(c, c, a);
    mul(a, d, f);
    mul(d, b, x);
    sqr(b, e);
    cswap(a, b, r);
    cswap(c, d, r);
}

void x25519_wide_ladder(uint8_t out[X25519_LEN], const uint8_t clamped[X25519_LEN],
                        const uint8_t point[X25519_LEN]) {
    fe x;
    fe a;
    fe b;
    fe c;
    fe d;
    fe e;
    fe f;
    unpack(x, point);
    for (size_t i = 0; i < 5; i++) {
        b[i] = x[i];
        a[i] = 0;
        c[i] = 0;
        d[i] = 0;
    }
    a[0] = 1;
    d[0] = 1;

    for (int i = 254; i >= 0; i--) {
        uint64_t r = (uint64_t)((clamped[i >> 3] >> (i & 7)) & 1);
        step(a, b, c, d, e, f, x, r);
    }
    invert(c, c);
    mul(a, a, c);
    pack(out, a);

    ct_wipe(a, sizeof a);
    ct_wipe(b, sizeof b);
    ct_wipe(c, sizeof c);
    ct_wipe(d, sizeof d);
    ct_wipe(e, sizeof e);
    ct_wipe(f, sizeof f);
}

#endif // CH_X25519_WIDE
