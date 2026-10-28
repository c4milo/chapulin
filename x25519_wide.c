// The wide X25519 field, which a host object holds beside x25519.c's
// (x25519_wide.h): the field arithmetic mod p = 2^255-19 and the Montgomery
// ladder of RFC 7748 section 5, in radix 2^51. An element is five words
// of 51 bits in uint64_t, and every product is one ct_mul128, the
// 64x64->128 multiply ct.h defines only for a host object. It runs the
// formulas of x25519.c's 16-word field on a tenth of the multiplies: 25
// products per field multiply instead of 256. Its ladder swaps the points
// once in each step, as RFC 7748 section 5 writes it and
// spec/lean/Spec/X25519.lean models it, where x25519.c swaps them twice
// (docs/decisions.md 152).
//
// The word bounds are INV-34 in docs/invariants.md, and every one of them
// is a claim a proof checks:
//
//   unpack        every word in [0, 2^51).
//   mul, sqr      operands' words under 2^54. Each product is under
//                 38 * 2^108, which is under 2^114; each column sums to
//                 under 77 * 2^108, which is under 2^115; and every carry
//                 between columns is under 2^64. Column 4 holds no product
//                 times 19, so it is under 5 * 2^108 and its carry is under
//                 2^60. The result's words are in [0, 2^51), except word 1
//                 in [0, 2^51 + 2^13).
//   mul_a24       operand words under 2^54; the result as for mul.
//   add           two results of mul, so each word under 2^53.
//   sub           a + 2p - b for two results of mul: b's words never pass
//                 2p's, so nothing wraps, and each word is under 2^53.
//
// So every operand the ladder hands mul or sqr is under 2^53, half the 2^54
// their proofs take. proof/x25519_wide_*_harness.c prove each line with
// --unsigned-overflow-check on, because unsigned arithmetic wraps silently
// in C and the default checks would see no wrap at all. The ladder proofs
// run a contract in place of the multiply, and they carry word 1 under
// 2^51 + 2^20 rather than 2^51 + 2^13; proof/x25519_wide_stubs.h says why.
//
// Constant time: no branch and no memory index depends on a word or on a
// scalar bit. cswap selects with a mask, the loops count public numbers,
// and the one instruction whose timing the C cannot state is the multiply,
// which is what the session's CH_CPU_CONSTANT_TIME_MULTIPLY bit states
// (cpu_cfg.h): widemul.h calls this file's entries for a session with the
// bit alone.
#include "x25519_wide.h"

#ifdef CH_CPU_RUNTIME

#include <stddef.h>

#include "ct.h"

// A field element: value = f[0] + f[1] 2^51 + f[2] 2^102 + f[3] 2^153 +
// f[4] 2^204, taken mod p. A word may exceed 51 bits between operations;
// the table above says by how much.
typedef uint64_t fe[5];

#define WORD_BITS 51
#define WORD_MASK ((UINT64_C(1) << WORD_BITS) - 1)

// a24 = (486662 - 2) / 4, the constant RFC 7748's ladder multiplies by.
#define A24 UINT64_C(121665)

// 2p, word by word: 2^52 - 38 at the bottom, 2^52 - 2 above it.
#define TWO_P_0 UINT64_C(0xFFFFFFFFFFFDA)
#define TWO_P_1_4 UINT64_C(0xFFFFFFFFFFFFE)

// The carry out of a column t: its bits from 51 up, as one word. The words of
// mul's and sqr's operands are under 2^54 (the table above), so each column is
// under 2^115 and the carry fits in 64 bits. The high half of t is multiplied
// by 2^13 rather than shifted, so that a column of 2^115 or more is an
// unsigned wrap, which --unsigned-overflow-check reports in every proof that
// runs this file. A shift would drop the same bits and report nothing. clang
// and gcc compile the multiply by a power of two to the shift (or, on arm64,
// to one EXTR with the low half).
static inline __attribute__((always_inline)) uint64_t column_carry(ct_u128 t) {
    return (uint64_t)(t >> 64) * (UINT64_C(1) << 13) | ((uint64_t)t >> WORD_BITS);
}

// Five column sums to five words. Each column keeps its low 51 bits and
// passes the rest to the next; what passes out of the top column is worth 19
// at the bottom, because 2^255 = 19 mod p, and the last carry from word 0
// goes to word 1 and stops there. Column 0's carry is added in 128 bits: the
// contract the ladder proofs run in place of the multiply cannot show that
// column 0 is under 2^115, and it shows that for the other four columns
// (proof/x25519_wide_stubs.h). The other carries and the fold of column 4's
// carry are words, as OpenSSL's fe51_mul writes them: column 4's carry is
// under 2^60, so 19 times it plus 51 bits stays under 2^64. A word of a sum
// is dropped nowhere, and an X25519 shared secret on a Neoverse-N2 runs
// 13,112 fewer instructions than with every carry in 128 bits
// (docs/decisions.md 152).
//
// mul_a24 calls it, and mul and sqr run the same carries between their
// columns (below). The attribute keeps it inside its caller. Without it gcc 13
// compiled it once, out of line, and each product and square passed it eleven
// words, six of them on x86-64's stack, where no wipe reaches them: an X25519
// shared secret took 61.4 µs on an EPYC 7763 that way and 54.5 µs inlined
// (docs/decisions.md 113). Both compilers of a host object read the
// attribute, and clang inlined the function already.
static inline __attribute__((always_inline)) void
carry_columns(fe o, ct_u128 t0, ct_u128 t1, ct_u128 t2, ct_u128 t3, ct_u128 t4) {
    t1 += t0 >> WORD_BITS;
    t2 += column_carry(t1);
    t3 += column_carry(t2);
    t4 += column_carry(t3);
    uint64_t r0 = ((uint64_t)t0 & WORD_MASK) + column_carry(t4) * 19;
    o[0] = r0 & WORD_MASK;
    o[1] = ((uint64_t)t1 & WORD_MASK) + (r0 >> WORD_BITS);
    o[2] = (uint64_t)t2 & WORD_MASK;
    o[3] = (uint64_t)t3 & WORD_MASK;
    o[4] = (uint64_t)t4 & WORD_MASK;
}

// The end of carry_columns for mul and sqr, which have kept the low 51 bits
// of columns 0 to 3 as r0 to r3 and carried into each next column already:
// column 4's carry, times 19, goes to word 0, and word 0's carry to word 1.
static inline __attribute__((always_inline)) void carry_top(fe o, uint64_t r0, uint64_t r1,
                                                            uint64_t r2, uint64_t r3, ct_u128 t4) {
    r0 += column_carry(t4) * 19;
    o[0] = r0 & WORD_MASK;
    o[1] = r1 + (r0 >> WORD_BITS);
    o[2] = r2;
    o[3] = r3;
    o[4] = (uint64_t)t4 & WORD_MASK;
}

// mul, sqr and mul_a24 carry the attribute too, so each of their calls is
// their code in place. Out of line, each call passed its operands through
// memory and the callers kept their values in the stack frame across it. In
// place, an X25519 shared secret runs 0.97 of the instructions on a
// Neoverse-N2, 0.89 under clang for x86-64 and 0.91 under gcc 13 for it, and
// the object holds 15 KB more code on arm64 and 14 KB more on x86-64
// (docs/decisions.md 152).

// o = a * b. Column k collects the products whose word indices sum to k, and
// the ones that sum to k + 5 come in times 19. Every word of a and b is read
// before o is written, so o may be a or b.
//
// Each column starts from the carry of the one below and keeps its low 51
// bits at once, so one column sum is live at a time: carry_columns' carries
// in its order, with each added before the column's products rather than
// after. With the five sums live together, clang 23 for x86-64 kept them in
// stack slots: a ladder step ran 1,807 instructions, 692 of them on the
// stack. In this form it runs 1,746, 491 on the stack. An X25519 shared
// secret takes 0.97 of its time under clang on an EPYC 7763 and on an M1
// Pro, and 0.95 on a Neoverse N2. Under gcc 13 it takes 0.99 on the N2, and
// its time on the EPYC does not move (docs/decisions.md 163).
static inline __attribute__((always_inline)) void mul(fe o, const fe a, const fe b) {
    uint64_t b1_19 = b[1] * 19;
    uint64_t b2_19 = b[2] * 19;
    uint64_t b3_19 = b[3] * 19;
    uint64_t b4_19 = b[4] * 19;
    ct_u128 t0 = ct_mul128(a[0], b[0]) + ct_mul128(a[1], b4_19) + ct_mul128(a[2], b3_19) +
                 ct_mul128(a[3], b2_19) + ct_mul128(a[4], b1_19);
    uint64_t r0 = (uint64_t)t0 & WORD_MASK;
    ct_u128 t1 = (t0 >> WORD_BITS) + ct_mul128(a[0], b[1]) + ct_mul128(a[1], b[0]) +
                 ct_mul128(a[2], b4_19) + ct_mul128(a[3], b3_19) + ct_mul128(a[4], b2_19);
    uint64_t r1 = (uint64_t)t1 & WORD_MASK;
    ct_u128 t2 = column_carry(t1) + ct_mul128(a[0], b[2]) + ct_mul128(a[1], b[1]) +
                 ct_mul128(a[2], b[0]) + ct_mul128(a[3], b4_19) + ct_mul128(a[4], b3_19);
    uint64_t r2 = (uint64_t)t2 & WORD_MASK;
    ct_u128 t3 = column_carry(t2) + ct_mul128(a[0], b[3]) + ct_mul128(a[1], b[2]) +
                 ct_mul128(a[2], b[1]) + ct_mul128(a[3], b[0]) + ct_mul128(a[4], b4_19);
    uint64_t r3 = (uint64_t)t3 & WORD_MASK;
    ct_u128 t4 = column_carry(t3) + ct_mul128(a[0], b[4]) + ct_mul128(a[1], b[3]) +
                 ct_mul128(a[2], b[2]) + ct_mul128(a[3], b[1]) + ct_mul128(a[4], b[0]);
    carry_top(o, r0, r1, r2, r3, t4);
}

// o = a * a: mul's columns with each pair of distinct words taken once and
// doubled, so 15 products instead of 25. The operands are ordered so the
// first is always under 2^55 and the second under 38 * 2^54, the domain
// proof/x25519_wide_stubs.h states for ct_mul128.
static inline __attribute__((always_inline)) void sqr(fe o, const fe a) {
    uint64_t a0_2 = a[0] * 2;
    uint64_t a1_2 = a[1] * 2;
    uint64_t a2_2 = a[2] * 2;
    uint64_t a3_19 = a[3] * 19;
    uint64_t a3_38 = a[3] * 38;
    uint64_t a4_19 = a[4] * 19;
    ct_u128 t0 = ct_mul128(a[0], a[0]) + ct_mul128(a1_2, a4_19) + ct_mul128(a2_2, a3_19);
    uint64_t r0 = (uint64_t)t0 & WORD_MASK;
    ct_u128 t1 =
        (t0 >> WORD_BITS) + ct_mul128(a[1], a0_2) + ct_mul128(a2_2, a4_19) + ct_mul128(a[3], a3_19);
    uint64_t r1 = (uint64_t)t1 & WORD_MASK;
    ct_u128 t2 =
        column_carry(t1) + ct_mul128(a[2], a0_2) + ct_mul128(a[1], a[1]) + ct_mul128(a[4], a3_38);
    uint64_t r2 = (uint64_t)t2 & WORD_MASK;
    ct_u128 t3 =
        column_carry(t2) + ct_mul128(a[3], a0_2) + ct_mul128(a[2], a1_2) + ct_mul128(a[4], a4_19);
    uint64_t r3 = (uint64_t)t3 & WORD_MASK;
    ct_u128 t4 =
        column_carry(t3) + ct_mul128(a[4], a0_2) + ct_mul128(a[3], a1_2) + ct_mul128(a[2], a[2]);
    carry_top(o, r0, r1, r2, r3, t4);
}

// o = a * a24.
static inline __attribute__((always_inline)) void mul_a24(fe o, const fe a) {
    carry_columns(o, ct_mul128(a[0], A24), ct_mul128(a[1], A24), ct_mul128(a[2], A24),
                  ct_mul128(a[3], A24), ct_mul128(a[4], A24));
}

// add, sub and cswap read every word before they write one, and name each
// word. gcc 13 compiled their loops to vector code behind a test of whether
// the operands overlap, a test of addresses and not of values. These forms
// take 0.93 of the instructions of an X25519 shared secret under gcc for
// x86-64, and clang's count changes by less than 0.3% (docs/decisions.md
// 152).

static void add(fe o, const fe a, const fe b) {
    uint64_t o0 = a[0] + b[0];
    uint64_t o1 = a[1] + b[1];
    uint64_t o2 = a[2] + b[2];
    uint64_t o3 = a[3] + b[3];
    uint64_t o4 = a[4] + b[4];
    o[0] = o0;
    o[1] = o1;
    o[2] = o2;
    o[3] = o3;
    o[4] = o4;
}

// o = a + 2p - b, which is a - b mod p with every word kept non-negative.
// It needs each word of b at or under 2p's, which every result of mul is.
static void sub(fe o, const fe a, const fe b) {
    uint64_t o0 = a[0] + TWO_P_0 - b[0];
    uint64_t o1 = a[1] + TWO_P_1_4 - b[1];
    uint64_t o2 = a[2] + TWO_P_1_4 - b[2];
    uint64_t o3 = a[3] + TWO_P_1_4 - b[3];
    uint64_t o4 = a[4] + TWO_P_1_4 - b[4];
    o[0] = o0;
    o[1] = o1;
    o[2] = o2;
    o[3] = o3;
    o[4] = o4;
}

// Swaps p and q when bit is 1 and leaves them when it is 0, without a
// branch. The mask is the bit moved to the top and spread down by an
// arithmetic shift, the form x25519.c's cswap takes for the reason its
// comment gives: gcc rewrites `x & -bit` as a multiply by the bit.
static void cswap(fe p, fe q, uint64_t bit) {
    uint64_t mask = (uint64_t)((int64_t)(bit << 63) >> 63);
    uint64_t t0 = mask & (p[0] ^ q[0]);
    uint64_t t1 = mask & (p[1] ^ q[1]);
    uint64_t t2 = mask & (p[2] ^ q[2]);
    uint64_t t3 = mask & (p[3] ^ q[3]);
    uint64_t t4 = mask & (p[4] ^ q[4]);
    p[0] ^= t0;
    p[1] ^= t1;
    p[2] ^= t2;
    p[3] ^= t3;
    p[4] ^= t4;
    q[0] ^= t0;
    q[1] ^= t1;
    q[2] ^= t2;
    q[3] ^= t3;
    q[4] ^= t4;
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

// The u-coordinate's 255 low bits into five words. RFC 7748 masks the top
// bit off. A value at or above p is kept as it is: mul reduces it like any
// other.
static void unpack(fe o, const uint8_t n[X25519_LEN]) {
    uint64_t w0 = load_le64(n);
    uint64_t w1 = load_le64(n + 8);
    uint64_t w2 = load_le64(n + 16);
    uint64_t w3 = load_le64(n + 24) & ~(UINT64_C(1) << 63);
    o[0] = w0 & WORD_MASK;
    o[1] = ((w0 >> 51) | (w1 << 13)) & WORD_MASK;
    o[2] = ((w1 >> 38) | (w2 << 26)) & WORD_MASK;
    o[3] = ((w2 >> 25) | (w3 << 39)) & WORD_MASK;
    o[4] = w3 >> 12;
}

// One pass of carries from each word into the next, the top one coming in
// at the bottom times 19. Two passes leave every word under 2^51 for any
// words under 2^63, which covers every value the ladder hands pack.
static void carry_words(uint64_t t[5]) {
    t[1] += t[0] >> WORD_BITS;
    t[0] &= WORD_MASK;
    t[2] += t[1] >> WORD_BITS;
    t[1] &= WORD_MASK;
    t[3] += t[2] >> WORD_BITS;
    t[2] &= WORD_MASK;
    t[4] += t[3] >> WORD_BITS;
    t[3] &= WORD_MASK;
    t[0] += (t[4] >> WORD_BITS) * 19;
    t[4] &= WORD_MASK;
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
    carry_words(t);
    carry_words(t);
    uint64_t q = (t[0] + 19) >> WORD_BITS;
    q = (t[1] + q) >> WORD_BITS;
    q = (t[2] + q) >> WORD_BITS;
    q = (t[3] + q) >> WORD_BITS;
    q = (t[4] + q) >> WORD_BITS;
    t[0] += 19 * q;
    t[1] += t[0] >> WORD_BITS;
    t[0] &= WORD_MASK;
    t[2] += t[1] >> WORD_BITS;
    t[1] &= WORD_MASK;
    t[3] += t[2] >> WORD_BITS;
    t[2] &= WORD_MASK;
    t[4] += t[3] >> WORD_BITS;
    t[3] &= WORD_MASK;
    t[4] &= WORD_MASK;
    store_le64(o, t[0] | (t[1] << 51));
    store_le64(o + 8, (t[1] >> 13) | (t[2] << 38));
    store_le64(o + 16, (t[2] >> 26) | (t[3] << 25));
    store_le64(o + 24, (t[3] >> 39) | (t[4] << 12));
    ct_wipe(t, sizeof t);
}

// One ladder step: x25519.c's step() over this field, with mul_a24 where
// that file multiplies by the constant element, and with one swap of the two
// points where that file has two. swap is the scalar bit of this step
// exclusive-or the bit of the step before, as RFC 7748 section 5 writes it:
// the second swap of a step and the first swap of the next one combine to one
// swap by that value. That removes two of the four cswap calls of each step,
// 9,140 instructions of a shared secret on a Neoverse-N2 (docs/decisions.md
// 152). A function of its own so
// proof/x25519_wide_step_harness.c can run one step and prove it keeps every
// word inside INV-34's bounds; the loop in x25519_wide_ladder() is the
// induction over it.
static void step(fe a, fe b, fe c, fe d, fe e, fe f, const fe x, uint64_t swap) {
    cswap(a, b, swap);
    cswap(c, d, swap);
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

    // After each step the points are swapped when bit is 1, and the next
    // step's swap undoes that. After the last step, a cswap by bit 0 undoes
    // it: a clamped scalar's bit 0 is 0, but the ladder does not depend on it.
    uint64_t bit = 0;
    for (int i = 254; i >= 0; i--) {
        uint64_t r = (uint64_t)((clamped[i >> 3] >> (i & 7)) & 1);
        step(a, b, c, d, e, f, x, bit ^ r);
        bit = r;
    }
    cswap(a, b, bit);
    cswap(c, d, bit);
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

// x25519_wide_base_mul, the key generation over a table of multiples of the base point, on
// this field.
#include "x25519_wide_edwards.h"

// The two entries, x25519_wide and x25519_wide_base. x25519.c holds the
// clamp and the all-zero check of both fields, so the two cannot differ:
// under CH_X25519_WIDE it compiles those alone, around x25519_wide_ladder,
// and the renames give its two entries this field's names.
#define CH_X25519_WIDE 1
#define x25519 x25519_wide
#define x25519_base x25519_wide_base
#include "x25519.c"

#endif // CH_CPU_RUNTIME
