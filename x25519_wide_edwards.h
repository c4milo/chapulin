// X25519 key generation for x25519_wide.c: the public key from a table of multiples of the base
// point, on the twisted Edwards form of the curve (docs/decisions.md 148). x25519_wide.c
// includes this file once, after its field, and no other source includes it. It is a header of
// its own so that x25519_wide.c stays under the 500 lines CLAUDE.md sets: every function here
// is static and compiles into x25519_wide.c's object, which a host object alone holds.
//
// The curves. edwards25519 is -x^2 + y^2 = 1 + d x^2 y^2 over the field of x25519_wide.c, with
// d = -121665 / 121666 (RFC 7748 section 4.1). The map u = (1 + y) / (1 - y) takes it to
// curve25519, the curve of the ladder, and it takes a sum of two points to the sum of their
// images. It takes B, the point whose y is 4/5, to the point whose u is 9. So the u of s * B is
// the u that the ladder computes for s and 9, and x25519_wide_base_mul computes s * B on
// edwards25519 and then that u. spec/lean/Spec/X25519Edwards.lean proves both facts and the
// formulas below, and bin/diff_x25519_wide holds the formulas to that model.
//
// The points. A point is (X : Y : Z : T), with x = X / Z, y = Y / Z and T = X Y / Z: the
// extended coordinates of Hisil, Wong, Carter and Dawson (2008). An addition writes a point in
// two halves, (E : H : G : F) with x = E / G and y = H / F, and four products take it back to
// (X : Y : Z : T). The addition and the doubling are the Explicit-Formulas Database's
// madd-2008-hwcd-3 and dbl-2008-hwcd for a = -1, as ref10 and BoringSSL write them. The
// addition is complete on this curve: d is not a square and -1 is, so no two points of the
// curve make a denominator zero (Bernstein, Birkner, Joye, Lange and Peters, 2008). The
// identity and a point and its negative need no special case.
//
// The scalar. A clamped scalar s is 64 digits of four bits, which recode() moves into
// [-8, 8]: s = e_0 + 16 e_1 + ... + 16^63 e_63. Row i of the table (x25519_wide_table.h) holds
// 1 to 8 times 256^i * B, so e_(2i+1) 256^i B and e_(2i) 256^i B each are one entry of row i,
// its negative, or the identity. x25519_wide_base_mul adds the 32 odd digits' entries, doubles
// the sum four times, and adds the 32 even digits' entries. That is 64 additions and four
// doublings, where the ladder runs 255 steps.
//
// The bounds. A word of a product or a square is under 2^51, except word 1 under 2^51 + 2^13
// (x25519_wide.c, INV-34). add() of two such values, and sub() of two, which adds 2p, leave
// each word under 2^53. The doubling adds 4p where it subtracts a value of two terms. The
// other sums here have one operand of two terms, and each word stays under 2^54, the bound the
// proofs of mul and sqr take for an operand. proof/x25519_wide_edwards_harness.c proves the
// bounds of an addition and a doubling.
//
// Constant time. recode() is arithmetic on every digit. select_entry() reads every entry of its
// row, in the same order whatever the digit, and keeps one by mask, and it negates by mask. So
// no address read and no branch depends on the scalar. The loops count public numbers, and the
// one instruction whose timing the C cannot state is the multiply, which the session's
// CH_CPU_CONSTANT_TIME_MULTIPLY bit states (cpu_cfg.h), as for the ladder.
#ifndef CH_X25519_WIDE_EDWARDS_H
#define CH_X25519_WIDE_EDWARDS_H

#include "x25519_wide_table.h"

#define DIGITS 64 // four-bit digits of a scalar

// 2p and 4p, word by word: 2^52 - 38 and 2^53 - 76 at the bottom, 2^52 - 2 and 2^53 - 4 above
// it.
static const fe TWO_P = {TWO_P_0, TWO_P_1_4, TWO_P_1_4, TWO_P_1_4, TWO_P_1_4};
static const fe FOUR_P = {UINT64_C(0x1FFFFFFFFFFFB4), UINT64_C(0x1FFFFFFFFFFFFC),
                          UINT64_C(0x1FFFFFFFFFFFFC), UINT64_C(0x1FFFFFFFFFFFFC),
                          UINT64_C(0x1FFFFFFFFFFFFC)};

// A point in extended coordinates: x = X / Z, y = Y / Z and T = X Y / Z.
typedef struct {
    fe x;
    fe y;
    fe z;
    fe t;
} edwards_point;

// A sum before its last four products: x = E / G and y = H / F.
typedef struct {
    fe e;
    fe h;
    fe g;
    fe f;
} edwards_sum;

// An entry of the table, or its negative, or the identity: y + x, y - x and 2 d x y of an
// affine point.
typedef struct {
    fe y_plus_x;
    fe y_minus_x;
    fe xy2d;
} edwards_entry;

// (a, b) = (a - b, a + b), word by word and in place: the difference with 2p added, as sub()
// adds it, so it needs each word of b at or under 2p's.
static void difference_and_sum(fe a, fe b) {
    for (size_t i = 0; i < 5; i++) {
        uint64_t first = a[i];
        a[i] = first + TWO_P[i] - b[i];
        b[i] = first + b[i];
    }
}

// The digits of a clamped scalar: s = e_0 + 16 e_1 + ... + 16^63 e_63, each e_i in [-8, 8].
// First each e_i is a four-bit nibble of s. Then, from the bottom, a digit of 8 or more gives
// 16 to the digit above it. Each step sees a nibble and a carry of 0 or 1, so a digit is at
// most 16 before the step and in [-8, 7] after it. The top nibble is at most 7, because the
// clamp clears bit 255, so e_63 is at most 8. Every step is arithmetic: the carry is a shift
// of a value that is never negative, and nothing branches on a digit.
static void recode(int64_t e[DIGITS], const uint8_t clamped[X25519_LEN]) {
    for (size_t i = 0; i < X25519_LEN; i++) {
        e[2 * i] = clamped[i] & 15;
        e[2 * i + 1] = (clamped[i] >> 4) & 15;
    }
    int64_t carry = 0;
    for (size_t i = 0; i < DIGITS - 1; i++) {
        e[i] += carry;
        carry = (e[i] + 8) >> 4;
        e[i] -= carry << 4;
    }
    e[DIGITS - 1] += carry;
}

// All ones when a and b are the same value and zero otherwise. a ^ b is zero exactly when the
// two are equal, and adding 2^64 - 1 to it, 128 bits wide so that nothing wraps, carries into
// bit 64 exactly when it is not zero. The mask is that bit moved to the top and spread down by
// an arithmetic shift, the form cswap() takes.
//
// The bit goes through a volatile object before the mask is built (docs/decisions.md 125).
// Without it, clang 23 for x86-64 saw that the mask is all ones exactly when a equals b, and it
// loaded word 4 of an entry under a jump on that comparison: a jump on the digit.
static uint64_t equal_mask(uint64_t a, uint64_t b) {
    volatile uint64_t differ = (uint64_t)(((ct_u128)(a ^ b) + UINT64_MAX) >> 64);
    uint64_t bit = differ ^ 1;
    return (uint64_t)((int64_t)(bit << 63) >> 63);
}

// Two words side by side, a GNU C vector type that gcc and clang compile to SSE2 or NEON
// registers and CBMC reads as two uint64_t, as p256_wide_mul.c's table_select uses it. & and |
// act on both words at once.
typedef uint64_t word_pair __attribute__((vector_size(16)));

// o = the entry for digit in a row of the table, for digit in [-8, 8]: row[j] holds j + 1 times
// the row's power of B. It reads all eight entries of the row, in the same order whatever the
// digit, and keeps the one at the digit's size by mask: each element's words 0 and 1 and words
// 2 and 3 as word_pair values, and word 4 alone. The size of a negative digit is its
// complement plus 1, which wraps nothing. A size of zero keeps no entry and sets the identity,
// (1, 1, 0). A negative digit then swaps y + x with y - x and takes 2p - 2dxy for 2dxy: the
// entry of (-x, y), the negative of (x, y). No address read and no branch depends on the
// digit.
static void select_entry(edwards_entry *o, const uint64_t row[X25519_WIDE_TABLE_ENTRIES][3][5],
                         int64_t digit) {
    uint64_t negative = (uint64_t)digit >> 63;
    uint64_t negative_mask = (uint64_t)((int64_t)(negative << 63) >> 63);
    uint64_t size = ((uint64_t)digit ^ negative_mask) + negative;
    word_pair low[3] = {
        {0, 0},
        {0, 0},
        {0, 0}
    };
    word_pair high[3] = {
        {0, 0},
        {0, 0},
        {0, 0}
    };
    uint64_t top[3] = {0, 0, 0};
    for (size_t j = 0; j < X25519_WIDE_TABLE_ENTRIES; j++) {
        uint64_t mask = equal_mask(size, j + 1);
        word_pair masks = {mask, mask};
        for (size_t element = 0; element < 3; element++) {
            word_pair entry_low = {row[j][element][0], row[j][element][1]};
            word_pair entry_high = {row[j][element][2], row[j][element][3]};
            low[element] |= entry_low & masks;
            high[element] |= entry_high & masks;
            top[element] |= row[j][element][4] & mask;
        }
    }
    uint64_t *out[3] = {o->y_plus_x, o->y_minus_x, o->xy2d};
    for (size_t element = 0; element < 3; element++) {
        out[element][0] = low[element][0];
        out[element][1] = low[element][1];
        out[element][2] = high[element][0];
        out[element][3] = high[element][1];
        out[element][4] = top[element];
    }
    uint64_t identity = equal_mask(size, 0);
    o->y_plus_x[0] |= identity & 1;
    o->y_minus_x[0] |= identity & 1;

    cswap(o->y_plus_x, o->y_minus_x, negative);
    for (size_t w = 0; w < 5; w++) {
        uint64_t minus = TWO_P[w] - o->xy2d[w];
        o->xy2d[w] ^= negative_mask & (o->xy2d[w] ^ minus);
    }
}

// o = a + b, for b an entry: madd-2008-hwcd-3 with Z2 = 1 and k = 2d, which b's third element
// already holds. A = (Y1 - X1)(y2 - x2), B = (Y1 + X1)(y2 + x2), C = T1 2dxy2 and D = 2 Z1, and
// the sum is E = B - A, H = B + A, G = D + C and F = D - C. Each value is written into o, so
// the sum leaves no copy on the stack for a wipe to find.
static void add_entry(edwards_sum *o, const edwards_point *a, const edwards_entry *b) {
    add(o->e, a->y, a->x);
    sub(o->h, a->y, a->x);
    mul(o->e, o->e, b->y_plus_x);  // B
    mul(o->h, o->h, b->y_minus_x); // A
    mul(o->g, a->t, b->xy2d);      // C
    add(o->f, a->z, a->z);         // D
    difference_and_sum(o->e, o->h);
    difference_and_sum(o->f, o->g);
}

// o = a + a: dbl-2008-hwcd with a = -1, which reads X, Y and Z alone. With XX = X^2, YY = Y^2
// and S = (X + Y)^2, the sum is H = YY + XX, G = YY - XX, E = S - H and F = 2 Z^2 - G. E and
// F subtract a value of two terms, so they add 4p. Each value is written into o, as in
// add_entry().
static void double_point(edwards_sum *o, const edwards_point *a) {
    sqr(o->e, a->x); // XX
    sqr(o->h, a->y); // YY
    sqr(o->f, a->z); // Z^2
    add(o->g, a->x, a->y);
    sqr(o->g, o->g); // S
    for (size_t i = 0; i < 5; i++) {
        uint64_t sum = o->h[i] + o->e[i];
        uint64_t difference = o->h[i] + TWO_P[i] - o->e[i];
        o->h[i] = sum;
        o->e[i] = o->g[i] + FOUR_P[i] - sum;
        o->g[i] = difference;
        o->f[i] = 2 * o->f[i] + FOUR_P[i] - difference;
    }
}

// o = the sum s in extended coordinates: X = E F, Y = G H, Z = G F and T = E H.
static void to_extended(edwards_point *o, const edwards_sum *s) {
    mul(o->x, s->e, s->f);
    mul(o->y, s->g, s->h);
    mul(o->z, s->g, s->f);
    mul(o->t, s->e, s->h);
}

// o = sum + the entry of digit in row. The row is a loop counter, and never the digit.
static void add_digit(edwards_point *sum, edwards_entry *entry, edwards_sum *partial, size_t row,
                      int64_t digit) {
    select_entry(entry, X25519_WIDE_TABLE[row], digit);
    add_entry(partial, sum, entry);
    to_extended(sum, partial);
}

// out = u = (1 + y) / (1 - y) = (Z + Y) / (Z - Y) of a point. Two carry passes take the
// denominator's words under 2^51, the form the ladder hands invert(). invert() takes zero to zero,
// so the identity, whose Z - Y is zero, gives 0.
static void to_u(uint8_t out[X25519_LEN], const edwards_point *p) {
    fe numerator;
    fe denominator;
    add(numerator, p->z, p->y);
    sub(denominator, p->z, p->y);
    carry_words(denominator);
    carry_words(denominator);
    invert(denominator, denominator);
    mul(numerator, numerator, denominator);
    pack(out, numerator);
    ct_wipe(numerator, sizeof numerator);
    ct_wipe(denominator, sizeof denominator);
}

void x25519_wide_base_mul(uint8_t out[X25519_LEN], const uint8_t clamped[X25519_LEN]) {
    int64_t e[DIGITS];
    edwards_point sum;
    edwards_sum partial;
    edwards_entry entry;
    recode(e, clamped);

    // The identity: x = 0 and y = 1.
    for (size_t w = 0; w < 5; w++) {
        sum.x[w] = 0;
        sum.y[w] = 0;
        sum.z[w] = 0;
        sum.t[w] = 0;
    }
    sum.y[0] = 1;
    sum.z[0] = 1;

    for (size_t row = 0; row < X25519_WIDE_TABLE_ROWS; row++) {
        add_digit(&sum, &entry, &partial, row, e[2 * row + 1]);
    }
    for (size_t i = 0; i < 4; i++) {
        double_point(&partial, &sum);
        to_extended(&sum, &partial);
    }
    for (size_t row = 0; row < X25519_WIDE_TABLE_ROWS; row++) {
        add_digit(&sum, &entry, &partial, row, e[2 * row]);
    }

    // s * B is not the identity, so Z - Y is not zero. B's order L is an odd prime above 2^252.
    // A clamped s is a multiple of 8, at least 2^254 and below 2^255, which is below 8 L, so L
    // does not divide it.
    to_u(out, &sum);

    ct_wipe(e, sizeof e);
    ct_wipe(&sum, sizeof sum);
    ct_wipe(&partial, sizeof partial);
    ct_wipe(&entry, sizeof entry);
}

#endif
