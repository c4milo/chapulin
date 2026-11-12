// The two P-256 scalar multiplications over the wide field (see p256_wide_mul.h for the
// contracts).
//
// Both write the scalar as signed odd digits, one for each window of w bits, and add one
// multiple of the point for each digit. p256_wide_base_mul reads its 43 six-bit windows and
// takes the multiple from the table of multiples of G (p256_wide_table.h), and never doubles.
// p256_wide_mul reads 64 four-bit windows and takes the multiple from eight multiples of its
// point, which it computes first, and doubles four times between windows. It runs in Jacobian
// coordinates, whose doubling takes 8 products where the homogeneous one took 10, and moves to
// homogeneous coordinates for its last window (docs/decisions.md 112). It moves the eight
// multiples to affine coordinates with one inverse, so each window adds its multiple by the mixed
// addition, 11 products where the Jacobian addition takes 16 (docs/decisions.md 224).
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
#include <string.h>

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

// Two words of a coordinate side by side, a GNU C vector type that gcc and clang compile to
// SSE2 or NEON registers and CBMC reads as two uint64_t. & and | act on both words at once.
typedef uint64_t word_pair __attribute__((vector_size(16)));

// All ones in each word where position and wanted hold the same value, and zero where they
// differ: a vector comparison sets each word of its result so, with no branch, on the vector
// registers that hold the scan's sums. The mask was a word in general registers, from a 128-bit
// sum, and gcc 13 moved it to a vector register for each entry: on an EPYC 7763 a key generation
// under gcc took 1.05 times its time with that mask (docs/decisions.md 212 and 224).
static inline word_pair equal_mask_pair(word_pair position, word_pair wanted) {
    return (word_pair)(position == wanted);
}

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
    const word_pair one = {1, 1};
    const word_pair wanted = {index, index};
    word_pair position = {0, 0};
    for (uint64_t j = 0; j < P256_WIDE_TABLE_ENTRIES; j++) {
        word_pair masks = equal_mask_pair(position, wanted);
        position += one;
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

// The same scan over the eight affine multiples of a point, with its four sums in word_pair
// values. The sums were *o's words, and each entry ORed into them in memory: a compiler cannot
// keep *o in registers across a read of row, because the two may be one object for all it can
// prove. Each word then passed through eight loads and eight stores, one after the other
// (docs/decisions.md 212).
static void multiple_select(p256_wide_affine *o, const p256_wide_affine row[ENTRIES],
                            uint64_t index) {
    word_pair x_low = {0, 0};
    word_pair x_high = {0, 0};
    word_pair y_low = {0, 0};
    word_pair y_high = {0, 0};
    const word_pair one = {1, 1};
    const word_pair wanted = {index, index};
    word_pair position = {0, 0};
    for (uint64_t j = 0; j < ENTRIES; j++) {
        word_pair keep = equal_mask_pair(position, wanted);
        position += one;
        word_pair multiple_x_low = {row[j].x.word[0], row[j].x.word[1]};
        word_pair multiple_x_high = {row[j].x.word[2], row[j].x.word[3]};
        word_pair multiple_y_low = {row[j].y.word[0], row[j].y.word[1]};
        word_pair multiple_y_high = {row[j].y.word[2], row[j].y.word[3]};
        x_low |= multiple_x_low & keep;
        x_high |= multiple_x_high & keep;
        y_low |= multiple_y_low & keep;
        y_high |= multiple_y_high & keep;
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

// affine[j] = multiple[j] in affine coordinates, x = X / Z^2 and y = Y / Z^3, with one inverse
// for the eight by Montgomery's trick. prefix[j] is the product of the Z of multiples 0 to j. From
// the inverse of all eight, the loop takes Z_j^-1 = prefix[j - 1] times the inverse of the
// product of the Z of multiples 0 to j, and then multiplies that inverse by Z_j to drop Z_j from
// it. spec/lean/Spec/P256WidePoint.lean proves the steps (batchInverse_mul_z). Where a Z is zero,
// so is the product, p256_wide_fe_inv's answer and every entry: p256_wide_mul catches the one
// case, a point at infinity, by a mask. Every value here is a secret's, and every step is the
// field's, so the steps read no value in a branch or an address.
static void multiples_to_affine(p256_wide_affine affine[ENTRIES],
                                const p256_wide_jacobian multiple[ENTRIES]) {
    p256_wide_fe prefix[ENTRIES];
    p256_wide_fe inverse;
    p256_wide_fe z_inverse;
    p256_wide_fe zz;
    prefix[0] = multiple[0].z;
    for (size_t j = 1; j < ENTRIES; j++) {
        p256_wide_fe_mul(&prefix[j], &prefix[j - 1], &multiple[j].z);
    }
    p256_wide_fe_inv(&inverse, &prefix[ENTRIES - 1]);
    for (size_t j = ENTRIES - 1; j > 0; j--) {
        p256_wide_fe_mul(&z_inverse, &inverse, &prefix[j - 1]);
        p256_wide_fe_mul(&inverse, &inverse, &multiple[j].z);
        p256_wide_fe_sqr(&zz, &z_inverse);
        p256_wide_fe_mul(&affine[j].x, &multiple[j].x, &zz);
        p256_wide_fe_mul(&zz, &zz, &z_inverse);
        p256_wide_fe_mul(&affine[j].y, &multiple[j].y, &zz);
    }
    p256_wide_fe_sqr(&zz, &inverse);
    p256_wide_fe_mul(&affine[0].x, &multiple[0].x, &zz);
    p256_wide_fe_mul(&zz, &zz, &inverse);
    p256_wide_fe_mul(&affine[0].y, &multiple[0].y, &zz);
    ct_wipe(prefix, sizeof prefix);
    ct_wipe(&inverse, sizeof inverse);
    ct_wipe(&z_inverse, sizeof z_inverse);
    ct_wipe(&zz, sizeof zz);
}

// o = a where mask is all ones, o unchanged where it is zero.
static void point_cmov(p256_wide_point *o, const p256_wide_point *a, uint64_t mask) {
    p256_wide_fe_cmov(&o->x, &a->x, mask);
    p256_wide_fe_cmov(&o->y, &a->y, mask);
    p256_wide_fe_cmov(&o->z, &a->z, mask);
}

// o = -o mod p where mask is all ones, and o where it is zero. 0 - o mod p is p - o for every o
// but zero, and zero for zero, as p256_wide_fe_neg computes it. Inline, where the two calls of
// p256_wide_fe_neg and p256_wide_fe_cmov took 2.4% of a key exchange under gcc 13.3 on an EPYC
// 7763 (docs/decisions.md 224). *negated is the caller's, so its wipe covers the negation.
static inline void conditional_negate(p256_wide_fe *o, p256_wide_fe *negated, uint64_t mask) {
    static const p256_wide_fe zero = {
        {0, 0, 0, 0}
    };
    p256_wide_fe_sub(negated, &zero, o);
    o->word[0] = (negated->word[0] & mask) | (o->word[0] & ~mask);
    o->word[1] = (negated->word[1] & mask) | (o->word[1] & ~mask);
    o->word[2] = (negated->word[2] & mask) | (o->word[2] & ~mask);
    o->word[3] = (negated->word[3] & mask) | (o->word[3] & ~mask);
}

// What the digit of one window adds, from the table of multiples of G: the entry of that
// window's row at the digit's size, with Y negated for a negative digit. *negated is the
// caller's, so that one wipe at the end of the multiplication covers it.
static void digit_entry(p256_wide_affine *o, p256_wide_fe *negated, const p256_scalar *k,
                        size_t window) {
    digit d = window_digit(k, window, P256_WIDE_TABLE_WINDOW_BITS, P256_WIDE_TABLE_WINDOWS);
    table_select(o, p256_wide_table[window], d.index);
    conditional_negate(&o->y, negated, d.negative);
}

// The same from the eight multiples of a point, multiple[j] = (2j + 1) times it, in affine
// coordinates.
static void digit_multiple(p256_wide_affine *o, p256_wide_fe *negated,
                           const p256_wide_affine multiple[ENTRIES], const p256_scalar *k,
                           size_t window) {
    digit d = window_digit(k, window, WINDOW_BITS, WINDOWS);
    multiple_select(o, multiple, d.index);
    conditional_negate(&o->y, negated, d.negative);
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
    // Windows 1 to 41 add by the incomplete addition, which needs a finite sum whose x is not
    // the entry's. Before window i the sum is S times G, for S the sum of d_j 64^j over the
    // windows j below i, and the entry is E times G, for E = d_i 64^i. Every digit is odd and at
    // most 63 in size, so S, S + E and S - E are odd, and so not zero, and are below 64^(i+1)
    // in size. For window 41 that is 2^252, which is below n, the order of G. So none of the
    // three is a multiple of n: the sum is finite and is neither the entry nor its negative.
    // spec/lean/Spec/P256WidePoint.lean proves it (windowSum_represents_p256).
    for (size_t window = 1; window + 1 < P256_WIDE_TABLE_WINDOWS; window++) {
        digit_entry(&entry, &negated, k, window);
        p256_wide_point_add_affine_incomplete(&sum, &sum, &entry);
    }
    // The top window keeps the complete addition, because there E = d_42 2^252 can exceed n.
    // For K = 0xe0000000ffffffff00000000000000004319055258e8617b0c46353d039cdaaf the sum before
    // it is S = 2^256 - n - 2^252 times G and the entry is E = 15 * 2^252 times G, so S - E = -n
    // and the sum is the entry.
    digit_entry(&entry, &negated, k, P256_WIDE_TABLE_WINDOWS - 1);
    p256_wide_point_add_affine(&sum, &sum, &entry);
    // The digits are those of k | 1, so an even k takes G away again: the sum plus -G is
    // computed for every k and kept by mask. This addition is complete too, because for
    // k = n - 1 the sum is the point at infinity.
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

// Four doublings: the sum moves up one four-bit window.
static void double_window(p256_wide_jacobian *sum) {
    for (int i = 0; i < WINDOW_BITS; i++) {
        p256_wide_point_double_jacobian(sum, sum);
    }
}

void p256_wide_mul(p256_point *o, const p256_scalar *k, const p256_point *p) {
    p256_wide_jacobian multiple[ENTRIES]; // multiple[j] = (2j + 1) * p
    p256_wide_affine affine[ENTRIES];     // the same in affine coordinates
    p256_wide_jacobian twice;
    p256_wide_jacobian sum;
    p256_wide_affine entry;
    p256_wide_point point;
    p256_wide_point total;
    p256_wide_point corrected;
    p256_wide_point infinity;
    p256_wide_fe negated;

    // n, the order of G, is prime and the curve has n points, so every finite point has order
    // n. Where p is the point at infinity, every multiple is too: the doubling's Z3 = Y1 Z1 and
    // the incomplete addition's Z3 = Z1 Z2 h are zero where Z1 is. Their affine forms are then
    // all zero, which is no point, so a mask on p's Z makes the answer the point at infinity at
    // the end.
    p256_wide_point_from_portable(&point, p);
    uint64_t at_infinity = p256_wide_fe_zero_mask(&point.z);
    p256_wide_point_to_jacobian(&multiple[0], &point);
    p256_wide_point_double_jacobian(&twice, &multiple[0]);
    // (2j + 1) p = (2j - 1) p + 2p, by the incomplete addition. Its condition holds: 2j - 1,
    // 2j - 3 and 2j + 1 are odd and at most 15 in size, so none is a multiple of n, and
    // (2j - 1) p is finite and is neither 2p nor -2p.
    for (size_t j = 1; j < ENTRIES; j++) {
        p256_wide_point_add_jacobian_incomplete(&multiple[j], &multiple[j - 1], &twice);
    }
    multiples_to_affine(affine, multiple);
    // Most significant window first: four doublings move the sum up one window, and the
    // window's digit adds its multiple. Windows 62 to 1 add by the incomplete addition, which
    // needs a finite sum whose x is not the entry's. Where window i adds its entry, the sum is
    // T times p, for T the sum of d_j 16^(j - i) over the windows j above i, and the entry is
    // d_i times p.
    // Every digit is odd and at most 15 in size, so T is 16 times an odd number, T + d_i and
    // T - d_i are odd, none of the three is zero, and all three are below 16^(64 - i) in size.
    // For window 1 that is 2^252, which is below n. So none of the three is a multiple of n:
    // the sum is finite and is neither the entry nor its negative.
    // spec/lean/Spec/P256WidePoint.lean proves it (ladderSum_represents_p256).
    digit_multiple(&entry, &negated, affine, k, WINDOWS - 1);
    sum.x = entry.x;
    sum.y = entry.y;
    sum.z = p256_wide_fe_one_mont;
    for (size_t window = WINDOWS - 1; window > 1; window--) {
        double_window(&sum);
        digit_multiple(&entry, &negated, affine, k, window - 1);
        p256_wide_point_add_jacobian_affine_incomplete(&sum, &sum, &entry);
    }
    // Window 0 keeps the complete addition, in homogeneous coordinates, because there T can
    // exceed n: for k = n - 2 the sum before it is n - 1 times p, which is -p, and the entry is
    // -p too.
    double_window(&sum);
    digit_multiple(&entry, &negated, affine, k, 0);
    p256_wide_point_from_jacobian(&total, &sum);
    p256_wide_point_add_affine(&total, &total, &entry);
    // The digits are those of k | 1, so an even k takes p away again: the total plus -p is
    // computed for every k and kept by mask. This addition is complete too, because for
    // k = n - 1 the total is the point at infinity.
    p256_wide_fe_neg(&point.y, &point.y);
    p256_wide_point_add(&corrected, &total, &point);
    point_cmov(&total, &corrected, p256_wide_mask(scalar_bit(k, 0) ^ 1U));
    // (0 : 1 : 0), the point at infinity, where p is.
    memset(&infinity, 0, sizeof infinity);
    infinity.y = p256_wide_fe_one_mont;
    point_cmov(&total, &infinity, at_infinity);
    p256_wide_point_to_portable(o, &total);

    ct_wipe(multiple, sizeof multiple);
    ct_wipe(affine, sizeof affine);
    ct_wipe(&twice, sizeof twice);
    ct_wipe(&sum, sizeof sum);
    ct_wipe(&entry, sizeof entry);
    ct_wipe(&point, sizeof point);
    ct_wipe(&total, sizeof total);
    ct_wipe(&corrected, sizeof corrected);
    ct_wipe(&negated, sizeof negated);
}

#endif // CH_CPU_RUNTIME
