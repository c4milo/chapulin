// The two P-256 scalar multiplications over the wide field (see p256_wide_mul.h for the
// contracts).
//
// Both write the scalar as signed odd digits, one for each window of w bits, and add one
// multiple of the point for each digit. p256_wide_base_mul reads its 43 six-bit windows and
// takes the multiple from the table of multiples of G (p256_wide_table.h), and never doubles.
// p256_wide_mul reads 64 four-bit windows and takes the multiple from eight multiples of its
// point, which it computes first, and doubles four times between windows.
//
// The digits. Both compute K times the point for K = k | 1, which is odd, and take the point
// away again when k was even. Write b_j for bit j of K, so b_0 is 1. Then
//
//     K = 2^255 + sum over j from 0 to 254 of s_j 2^j,  with s_j = 2 b_(j+1) - 1,
//
// because the sum is (K - 1) - (2^255 - 1). Each s_j is +1 or -1: +1 when the bit above
// position j is set. w of them make the digit of window i,
//
//     d_i = s_(wi) + 2 s_(wi+1) + ... + 2^(w-1) s_(wi+w-1),
//
// with the 2^255 term standing in for s_255 and no term above it, so K is the sum of
// d_i 2^(wi). A digit is odd and lies between -(2^w - 1) and 2^w - 1, and none is zero, so every
// window adds exactly one multiple and the sequence of operations is the same for every
// scalar. A digit's sign is the sign of its top term, s_(wi+w-1): positive when bit wi + w of k
// is set, and always positive for the top window, whose top term is the 2^255 term. With v the
// w - 1 bits wi + 1 to wi + w - 1 of k, a bit above 255 read as zero, a positive digit is
// 2v + 1 and a negative one is -(2 (2^(w-1) - 1 - v) + 1). Six-bit windows end in a window of
// four terms, s_252 to the 2^255 term, whose digit lies between 1 and 15. Bit 0 of k is read
// once, for the correction at the end: K's bit 0 is 1 whatever k's is.
// proof/p256_wide_digit_harness.c proves that the digits add up to k | 1 for every k, at both
// widths.
#include "p256_wide_mul.h"

#ifdef CH_CPU_RUNTIME

#include <stddef.h>

#include "ct.h"
#include "p256_wide_field.h"
#include "p256_wide_point.h"
#include "p256_wide_table.h"
#include "p256_wide_word.h"

// p256_wide_mul's windows: 64 of four bits, over the eight odd multiples of its point up to 15.
// p256_wide_base_mul's are p256_wide_table.h's.
#define WINDOW_BITS 4
#define WINDOWS 64
#define ENTRIES 8

static const p256_wide_fe FE_ZERO = {
    {0, 0, 0, 0}
};

// Bit i of k, for i below 256.
static inline uint64_t scalar_bit(const p256_scalar *k, size_t i) {
    return (k->word[i >> 5] >> (i & 31)) & 1U;
}

// Bit i of k, and zero for i above 255, where a top window reads past the scalar. The test
// reads i, a count of windows and bits, and never the scalar.
static inline uint64_t scalar_bit_or_zero(const p256_scalar *k, size_t i) {
    if (i > 255) {
        return 0;
    }
    return scalar_bit(k, i);
}

// All ones when a and b are the same value and zero otherwise. a ^ b is zero exactly when the
// two are equal, and adding 2^64 - 1 to it, 128 bits wide so that nothing wraps, carries into
// bit 64 exactly when it is not zero.
static inline uint64_t equal_mask(uint64_t a, uint64_t b) {
    uint64_t differ = (uint64_t)(((ct_u128)(a ^ b) + UINT64_MAX) >> 64);
    return p256_wide_mask(differ ^ 1U);
}

// One digit of k | 1.
typedef struct {
    uint64_t index;    // where its size sits among the odd multiples: 0 for 1, 7 for 15
    uint64_t negative; // all ones for a negative digit, zero for a positive one
} digit;

// The digit of one window of k | 1, for windows of bits bits, windows of them, and window below
// windows. Its index is below 2^(bits - 1).
static digit window_digit(const p256_scalar *k, size_t window, size_t bits, size_t windows) {
    size_t low = bits * window;
    uint64_t size = 0;
    for (size_t t = 1; t < bits; t++) {
        size |= scalar_bit_or_zero(k, low + t) << (t - 1);
    }
    // The top window's sign is the 2^255 term's. The test reads the window, a loop counter,
    // and never the scalar.
    uint64_t positive = 1;
    if (window + 1 < windows) {
        positive = scalar_bit(k, low + bits);
    }
    uint64_t largest_index = ((uint64_t)1 << (bits - 1)) - 1;
    digit d;
    d.negative = p256_wide_mask(positive ^ 1U);
    d.index = size ^ (d.negative & largest_index);
    return d;
}

// o |= a where mask is all ones, and o unchanged where it is zero.
static inline void fe_keep(p256_wide_fe *o, const p256_wide_fe *a, uint64_t mask) {
    for (size_t i = 0; i < P256_WIDE_FE_WORDS; i++) {
        o->word[i] |= a->word[i] & mask;
    }
}

// Two words of a coordinate side by side, a GNU C vector type that gcc and clang compile to
// SSE2 or NEON registers and CBMC reads as two uint64_t. & and | act on both words at once.
typedef uint64_t word_pair __attribute__((vector_size(16)));

// o = row[index], for index below P256_WIDE_TABLE_ENTRIES. It reads every entry of the row, in
// the same order whatever index holds, and keeps one by mask: no address read and no branch
// depends on index. A row holds 32 entries, so the scan keeps its four sums in word_pair
// values, which the compiler keeps in vector registers, and reads an entry four vectors at a
// time (docs/decisions.md 109).
static void table_select(p256_wide_affine *o, const p256_wide_affine row[P256_WIDE_TABLE_ENTRIES],
                         uint64_t index) {
    word_pair x_low = {0, 0};
    word_pair x_high = {0, 0};
    word_pair y_low = {0, 0};
    word_pair y_high = {0, 0};
    for (uint64_t j = 0; j < P256_WIDE_TABLE_ENTRIES; j++) {
        uint64_t mask = equal_mask(j, index);
        word_pair masks = {mask, mask};
        word_pair entry_x_low = {row[j].x.word[0], row[j].x.word[1]};
        word_pair entry_x_high = {row[j].x.word[2], row[j].x.word[3]};
        word_pair entry_y_low = {row[j].y.word[0], row[j].y.word[1]};
        word_pair entry_y_high = {row[j].y.word[2], row[j].y.word[3]};
        x_low |= entry_x_low & masks;
        x_high |= entry_x_high & masks;
        y_low |= entry_y_low & masks;
        y_high |= entry_y_high & masks;
    }
    o->x.word[0] = x_low[0];
    o->x.word[1] = x_low[1];
    o->x.word[2] = x_high[0];
    o->x.word[3] = x_high[1];
    o->y.word[0] = y_low[0];
    o->y.word[1] = y_low[1];
    o->y.word[2] = y_high[0];
    o->y.word[3] = y_high[1];
}

// The same scan over eight projective points.
static void multiple_select(p256_wide_point *o, const p256_wide_point row[ENTRIES],
                            uint64_t index) {
    o->x = FE_ZERO;
    o->y = FE_ZERO;
    o->z = FE_ZERO;
    for (uint64_t j = 0; j < ENTRIES; j++) {
        uint64_t mask = equal_mask(j, index);
        fe_keep(&o->x, &row[j].x, mask);
        fe_keep(&o->y, &row[j].y, mask);
        fe_keep(&o->z, &row[j].z, mask);
    }
}

// o = a where mask is all ones, o unchanged where it is zero.
static void point_cmov(p256_wide_point *o, const p256_wide_point *a, uint64_t mask) {
    p256_wide_fe_cmov(&o->x, &a->x, mask);
    p256_wide_fe_cmov(&o->y, &a->y, mask);
    p256_wide_fe_cmov(&o->z, &a->z, mask);
}

// What the digit of one window adds, from the table of multiples of G: the entry of that
// window's row at the digit's size, with Y negated for a negative digit. *negated is the
// caller's, so that one wipe at the end of the multiplication covers it.
static void digit_entry(p256_wide_affine *o, p256_wide_fe *negated, const p256_scalar *k,
                        size_t window) {
    digit d = window_digit(k, window, P256_WIDE_TABLE_WINDOW_BITS, P256_WIDE_TABLE_WINDOWS);
    table_select(o, p256_wide_table[window], d.index);
    p256_wide_fe_neg(negated, &o->y);
    p256_wide_fe_cmov(&o->y, negated, d.negative);
}

// The same from the eight multiples of a point, multiple[j] = (2j + 1) times it.
static void digit_multiple(p256_wide_point *o, p256_wide_fe *negated,
                           const p256_wide_point multiple[ENTRIES], const p256_scalar *k,
                           size_t window) {
    digit d = window_digit(k, window, WINDOW_BITS, WINDOWS);
    multiple_select(o, multiple, d.index);
    p256_wide_fe_neg(negated, &o->y);
    p256_wide_fe_cmov(&o->y, negated, d.negative);
}

void p256_wide_base_mul(p256_point *o, const p256_scalar *k) {
    p256_wide_point sum;
    p256_wide_point corrected;
    p256_wide_affine entry;
    p256_wide_fe negated;

    // Window 0 starts the sum. Its entry is a finite point, so Z is 1.
    digit_entry(&entry, &negated, k, 0);
    sum.x = entry.x;
    sum.y = entry.y;
    sum.z = p256_wide_fe_one_mont;
    for (size_t window = 1; window < P256_WIDE_TABLE_WINDOWS; window++) {
        digit_entry(&entry, &negated, k, window);
        p256_wide_point_add_affine(&sum, &sum, &entry);
    }
    // The digits are those of k | 1, so an even k takes G away again: the sum plus -G is
    // computed for every k and kept by mask.
    entry = p256_wide_table[0][0];
    p256_wide_fe_neg(&entry.y, &entry.y);
    p256_wide_point_add_affine(&corrected, &sum, &entry);
    point_cmov(&sum, &corrected, p256_wide_mask(scalar_bit(k, 0) ^ 1U));
    p256_wide_point_to_portable(o, &sum);

    ct_wipe(&sum, sizeof sum);
    ct_wipe(&corrected, sizeof corrected);
    ct_wipe(&entry, sizeof entry);
    ct_wipe(&negated, sizeof negated);
}

void p256_wide_mul(p256_point *o, const p256_scalar *k, const p256_point *p) {
    p256_wide_point multiple[ENTRIES]; // multiple[j] = (2j + 1) * p
    p256_wide_point twice;
    p256_wide_point sum;
    p256_wide_point entry;
    p256_wide_point corrected;
    p256_wide_fe negated;

    p256_wide_point_from_portable(&multiple[0], p);
    p256_wide_point_double(&twice, &multiple[0]);
    for (size_t j = 1; j < ENTRIES; j++) {
        p256_wide_point_add(&multiple[j], &multiple[j - 1], &twice);
    }
    // Most significant window first: four doublings move the sum up one window, and the
    // window's digit adds its multiple.
    digit_multiple(&sum, &negated, multiple, k, WINDOWS - 1);
    for (size_t window = WINDOWS - 1; window > 0; window--) {
        for (int i = 0; i < WINDOW_BITS; i++) {
            p256_wide_point_double(&sum, &sum);
        }
        digit_multiple(&entry, &negated, multiple, k, window - 1);
        p256_wide_point_add(&sum, &sum, &entry);
    }
    // The digits are those of k | 1, so an even k takes p away again, by mask.
    entry = multiple[0];
    p256_wide_fe_neg(&entry.y, &entry.y);
    p256_wide_point_add(&corrected, &sum, &entry);
    point_cmov(&sum, &corrected, p256_wide_mask(scalar_bit(k, 0) ^ 1U));
    p256_wide_point_to_portable(o, &sum);

    ct_wipe(multiple, sizeof multiple);
    ct_wipe(&twice, sizeof twice);
    ct_wipe(&sum, sizeof sum);
    ct_wipe(&entry, sizeof entry);
    ct_wipe(&corrected, sizeof corrected);
    ct_wipe(&negated, sizeof negated);
}

#endif // CH_CPU_RUNTIME
