// RSA's Montgomery arithmetic on 64-bit words, which a host object holds
// (rsa_mont64.h): the multiplication, the square, the constant R^2 mod m
// that moves a number into the Montgomery domain, and the public
// operation, base^65537 mod m.
//
// Every sum here is written so that it cannot wrap. A product is one
// ct_mul128, at most (2^64 - 1)^2, and two more words fit above it in 128
// bits: (2^64 - 1)^2 + 2 * (2^64 - 1) = 2^128 - 1. A subtraction adds the
// complement of the subtrahend and one, and reads the carry where a
// borrow would be. proof/rsa_mont64_sums_harness.c and
// proof/rsa_mont64_ops_harness.c run with --unsigned-overflow-check on,
// the first over contracts of ct_mul128 and of rsa_mont64.h's step, so
// each of those sums is a property CBMC checks. Two pieces wrap on
// purpose, modulo 2^64: neg_inverse, which proof/rsa_mont64_init_harness.c
// runs with that check off, and, in the form clang reads, the two adds of
// the step the inner loops call, rsa_mont64_mul_add_add, which
// proof/rsa_mont64_step_harness.c proves equal to the sum the contract
// takes.
//
// Constant time: no branch and no memory index depends on a word. The
// branches the file compiles to are loops over word and byte counts, the
// doublings rsa_mont64_modulus_init counts from its bits argument, the
// sixteen squarings of the public exponent, the square's tests of a row's
// index, and the CH_ASSERTs on public lengths.
#include "rsa_mont64.h"

#ifdef CH_CPU_RUNTIME

#include <string.h>

#include "ch_assert.h"
#include "ct.h"
#include "rsa_mont64_blocks.h"

// All ones when bit is 1, all zeros when bit is 0. The mask comes from
// moving the bit to the top and spreading it down with an arithmetic
// shift, the form rsa_sign.c's mask_of_bit takes for the reason its
// comment gives: gcc rewrites `x & -bit` as a multiply by the bit.
static uint64_t mask_of_bit(uint64_t bit) {
    return (uint64_t)((int64_t)(bit << 63) >> 63);
}

void rsa_mont64_from_bytes(uint64_t *words, size_t count, const uint8_t *bytes, size_t len) {
    memset(words, 0, count * sizeof(uint64_t));
    // Byte i from the end has weight 2^(8i): word i / 8, shifted up
    // 8 * (i % 8) bits.
    for (size_t i = 0; i < len; i++) {
        words[i >> 3] |= (uint64_t)bytes[len - 1 - i] << (8 * (i & 7));
    }
}

void rsa_mont64_to_bytes(uint8_t *bytes, size_t len, const uint64_t *words) {
    for (size_t i = 0; i < len; i++) {
        bytes[len - 1 - i] = (uint8_t)(words[i >> 3] >> (8 * (i & 7)));
    }
}

// 1 when the k + 1 word value top:a is at or above m, and 0 when it is
// below. It adds the complement of m and one, word by word, which is
// a - m with no step that wraps, and the carry out of the top word is the
// answer: a subtraction that does not borrow carries here. m has no word
// above k, so the top word adds the complement of zero.
static uint64_t at_or_above(const uint64_t *a, uint64_t top, const uint64_t *m, size_t k) {
    uint64_t carry = 1;
    for (size_t i = 0; i < k; i++) {
        ct_u128 v = (ct_u128)a[i] + ~m[i] + carry;
        carry = (uint64_t)(v >> 64);
    }
    return (uint64_t)(((ct_u128)top + UINT64_MAX + carry) >> 64);
}

// o = a - (m & mask) over k words, by the same sum. mask is all ones or
// all zeros, so this is the whole subtraction or a subtraction of zero,
// and both take the same time and write the same words. o may be a.
static void sub_masked(uint64_t *o, const uint64_t *a, const uint64_t *m, size_t k, uint64_t mask) {
    uint64_t carry = 1;
    for (size_t i = 0; i < k; i++) {
        ct_u128 v = (ct_u128)a[i] + ~(m[i] & mask) + carry;
        o[i] = (uint64_t)v;
        carry = (uint64_t)(v >> 64);
    }
}

// o = top:a - m when top:a is at or above m, and a when it is below: one
// subtraction of m, chosen by a mask. For top:a below 2m the result is
// top:a mod m. o may be a.
static void reduce_once(uint64_t *o, const uint64_t *a, uint64_t top, const uint64_t *m, size_t k) {
    sub_masked(o, a, m, k, mask_of_bit(at_or_above(a, top, m, k)));
}

// x = 2x mod m, for x below m: a shift up by one bit, the bit that leaves
// the top word kept as the word above, and one subtraction.
static void double_mod(uint64_t *x, const uint64_t *m, size_t k) {
    uint64_t moved = 0;
    for (size_t i = 0; i < k; i++) {
        uint64_t next = x[i] >> 63;
        x[i] = (x[i] << 1) | moved;
        moved = next;
    }
    reduce_once(x, x, moved, m, k);
}

// x = 2^bit over k words, for a bit below 64 * k.
static void power_of_two(uint64_t *x, size_t k, size_t bit) {
    memset(x, 0, k * sizeof(uint64_t));
    x[bit >> 6] = (uint64_t)1 << (bit & 63);
}

// -m0^-1 mod 2^64, by Newton's iteration. m0 is odd, so x = 1 is the
// inverse to one bit, and each step doubles the bits that are right: six
// steps make 64. This arithmetic is modulo 2^64, so it wraps on purpose.
static uint64_t neg_inverse(uint64_t m0) {
    uint64_t x = 1;
    for (int i = 0; i < 6; i++) {
        x *= 2U - m0 * x;
    }
    return 0U - x;
}

#if RSA_MONT64_BLOCKS
// The multiplication on rsa_mont64_blocks.c's blocks, for a word count that is a multiple of 4.
// Their product goes to r, apart from a and b, which o may be, and the last subtraction moves it
// to o.
static void mont_mul_blocks(uint64_t *o, const uint64_t *a, const uint64_t *b,
                            const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    uint64_t r[RSA_MONT64_WORDS_MAX];
    uint64_t top = rsa_mont64_blocks_mul(r, a, b, mod);
    reduce_once(o, r, top, mod->m, k);
    ct_wipe(r, k * sizeof(uint64_t));
}

// The square on the blocks, for a word count that is a multiple of 4: up to
// RSA_MONT64_SQUARE_AS_MUL_WORDS_MAX words as their multiplication of a by itself, and above it
// as their square.
static void mont_square_blocks(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    uint64_t r[RSA_MONT64_WORDS_MAX];
    uint64_t top;
    if (k <= RSA_MONT64_SQUARE_AS_MUL_WORDS_MAX) {
        top = rsa_mont64_blocks_mul(r, a, a, mod);
    } else {
        top = rsa_mont64_blocks_square(r, a, mod);
    }
    reduce_once(o, r, top, mod->m, k);
    ct_wipe(r, k * sizeof(uint64_t));
}
#endif

void rsa_mont64_mont_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                         const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    const uint64_t *m = mod->m;
#if RSA_MONT64_BLOCKS
    if (k % 4 == 0) {
        mont_mul_blocks(o, a, b, mod);
        return;
    }
#endif
    // t is k + 2 words. The first k + 1 are the running sum, below 2m
    // after every round when b is below m, so its top word is 0 or 1. The
    // word above them holds u, the round's multiple of m.
    uint64_t t[RSA_MONT64_WORDS_MAX + 2];
    memset(t, 0, (k + 2) * sizeof(uint64_t));
    // Five values are read once a round or once a product and are the
    // same for a whole round: b[0], m[0], m0inv, the round's word a[i]
    // and u. A compiler loads such a value before the loop that uses it,
    // and when it runs out of registers it keeps the copy in a stack slot
    // of its own, which ct_wipe cannot name. Apple clang 21 for x86-64
    // left b[0] in one, and gcc 13 for x86-64 left a[i] and u, and the
    // residue check in bin/rsa_sign_equiv_test found b[0] and a[i]. So
    // each is read through a volatile pointer where a product uses it,
    // and no copy outlives the product. u is computed here and has no
    // other home, so it is kept in t's last word, which the wipe below
    // covers.
    const volatile uint64_t *b_first = b;
    const volatile uint64_t *m_first = m;
    const volatile uint64_t *m0inv = &mod->m0inv;
    volatile uint64_t *u = &t[k + 1];
    // Round i adds a[i] * b and u * m to t and moves t down one word. u is
    // the multiple of m that makes the low word of that sum zero, which is
    // what lets the word go. One pass over the words carries both
    // products, each with its own carry: the sum of the a[i] * b terms
    // feeds the sum of the u * m terms, word by word.
    for (size_t i = 0; i < k; i++) {
        const volatile uint64_t *a_word = &a[i];
        ct_u128 ab = ct_mul128(*a_word, *b_first) + t[0];
        // u is the low word of that sum times m0inv, modulo 2^64: the
        // low half of one more product.
        *u = (uint64_t)ct_mul128((uint64_t)ab, *m0inv);
        ct_u128 um = ct_mul128(*u, *m_first) + (uint64_t)ab;
        uint64_t ab_carry = (uint64_t)(ab >> 64);
        uint64_t um_carry = (uint64_t)(um >> 64);
        for (size_t j = 1; j < k; j++) {
            rsa_mont64_sum ab_sum = rsa_mont64_mul_add_add(*a_word, b[j], t[j], ab_carry);
            ab_carry = ab_sum.high;
            rsa_mont64_sum um_sum = rsa_mont64_mul_add_add(*u, m[j], ab_sum.low, um_carry);
            um_carry = um_sum.high;
            t[j - 1] = um_sum.low;
        }
        ct_u128 top = (ct_u128)t[k] + ab_carry + um_carry;
        t[k - 1] = (uint64_t)top;
        t[k] = (uint64_t)(top >> 64);
    }
    reduce_once(o, t, t[k], m, k);
    // t held a * b / R before its last subtraction, which is as secret as
    // the product, and the last round's u above it.
    ct_wipe(t, (k + 2) * sizeof(uint64_t));
}

// The square of a is the sum over i of a_i B^i V_i, where B = 2^64 and
// V_i = a_i B^i + 2 (a_{i+1} B^{i+1} + ... + a_{k-1} B^{k-1}): each
// product a_i a_j with i < j once, doubled, in row i, and each square
// once. V_i's words are a_i at word i, a_{i+1} shifted up one bit at word
// i + 1, and above them the words of 2a, which d holds: d_j is a_j shifted
// up one bit with the top bit of a_{j-1} below it, and d_k is the top bit
// of a_{k-1}, 0 or 1.
//
// Row i is a round of rsa_mont64_mont_mul's one pass with a_i V_i in place
// of a[i] * b. a_i V_i starts at word 2i, which is offset i of the running
// sum, so below offset i the row adds u * m alone, and u comes from the
// sum's low word before the row adds anything to it. Row 0 is the one
// exception: its square lands at offset 0, so its u comes after.
//
// The running sum is below 3m after each row, so its top word is 0, 1 or
// 2: the rows up to i add up to less than (a_0 + ... + a_i B^i) 2a, which
// is below B^(i+1) 2m. After the last row the sum is (a^2 + u m) / R, below
// 2m, and one subtraction chosen by a mask ends it. Each sum is at most a
// product and two words, as in rsa_mont64_mont_mul, and the step at offset
// k adds a_i under the mask of d_k and multiplies nothing.
//
// a_i and u, which a row reads at every product, and m[0], m0inv and d_k,
// which it reads once, are read through volatile pointers, and u is kept
// in t's last word, for the reason rsa_mont64_mont_mul gives: no copy a
// compiler makes of them outlives the product that uses it. d_k is the top
// bit of a, and the mask a row makes of it is the same for every row: gcc
// 13 for x86-64 made it once, before the rows, and kept it in a stack slot
// of its own, which bin/rsa_sign_equiv_test's two stacks found.
void rsa_mont64_mont_square(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    const uint64_t *m = mod->m;
#if RSA_MONT64_BLOCKS
    if (k % 4 == 0) {
        mont_square_blocks(o, a, mod);
        return;
    }
#endif
    uint64_t d[RSA_MONT64_WORDS_MAX + 1];
    uint64_t t[RSA_MONT64_WORDS_MAX + 2];
    uint64_t moved = 0;
    for (size_t j = 0; j < k; j++) {
        d[j] = (a[j] << 1) | moved;
        moved = a[j] >> 63;
        t[j] = 0;
    }
    d[k] = moved;
    t[k] = 0;
    t[k + 1] = 0;
    const volatile uint64_t *m_first = m;
    const volatile uint64_t *m0inv = &mod->m0inv;
    const volatile uint64_t *d_top = &d[k];
    volatile uint64_t *u = &t[k + 1];
    for (size_t i = 0; i < k; i++) {
        const volatile uint64_t *a_word = &a[i];
        uint64_t ab_carry;
        uint64_t um_carry;
        if (i == 0) {
            ct_u128 ab = ct_mul128(*a_word, *a_word) + t[0];
            *u = (uint64_t)ct_mul128((uint64_t)ab, *m0inv);
            ct_u128 um = ct_mul128(*u, *m_first) + (uint64_t)ab;
            ab_carry = (uint64_t)(ab >> 64);
            um_carry = (uint64_t)(um >> 64);
        } else {
            *u = (uint64_t)ct_mul128(t[0], *m0inv);
            ct_u128 um = ct_mul128(*u, *m_first) + t[0];
            um_carry = (uint64_t)(um >> 64);
            for (size_t j = 1; j < i; j++) {
                rsa_mont64_sum um_sum = rsa_mont64_mul_add_add(*u, m[j], t[j], um_carry);
                um_carry = um_sum.high;
                t[j - 1] = um_sum.low;
            }
            // Offset i: the square.
            ct_u128 ab = ct_mul128(*a_word, *a_word) + t[i];
            ab_carry = (uint64_t)(ab >> 64);
            um = ct_mul128(*u, m[i]) + (uint64_t)ab + um_carry;
            um_carry = (uint64_t)(um >> 64);
            t[i - 1] = (uint64_t)um;
        }
        if (i + 1 < k) {
            // Offset i + 1: a_i times a_{i+1} shifted up one bit.
            ct_u128 ab = ct_mul128(*a_word, a[i + 1] << 1) + t[i + 1] + ab_carry;
            ab_carry = (uint64_t)(ab >> 64);
            ct_u128 um = ct_mul128(*u, m[i + 1]) + (uint64_t)ab + um_carry;
            um_carry = (uint64_t)(um >> 64);
            t[i] = (uint64_t)um;
            // Offsets i + 2 to k - 1: a_i times the words of 2a.
            for (size_t j = i + 2; j < k; j++) {
                rsa_mont64_sum ab_sum = rsa_mont64_mul_add_add(*a_word, d[j], t[j], ab_carry);
                ab_carry = ab_sum.high;
                rsa_mont64_sum um_sum = rsa_mont64_mul_add_add(*u, m[j], ab_sum.low, um_carry);
                um_carry = um_sum.high;
                t[j - 1] = um_sum.low;
            }
            // Offset k: a_i times d_k, which is 0 or 1, so a_i under a mask.
            ct_u128 sum = (ct_u128)(*a_word & mask_of_bit(*d_top)) + t[k] + ab_carry;
            ct_u128 top = (ct_u128)(uint64_t)sum + um_carry;
            t[k - 1] = (uint64_t)top;
            t[k] = (uint64_t)(sum >> 64) + (uint64_t)(top >> 64);
        } else {
            ct_u128 top = (ct_u128)t[k] + ab_carry + um_carry;
            t[k - 1] = (uint64_t)top;
            t[k] = (uint64_t)(top >> 64);
        }
    }
    reduce_once(o, t, t[k], m, k);
    // d is twice a, and t held a^2 / R before its last subtraction and the
    // last row's u above it: as secret as a.
    ct_wipe(d, (k + 1) * sizeof(uint64_t));
    ct_wipe(t, (k + 2) * sizeof(uint64_t));
}

void rsa_mont64_add(uint64_t *o, const uint64_t *a, const uint64_t *b,
                    const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    uint64_t carry = 0;
    for (size_t i = 0; i < k; i++) {
        ct_u128 v = (ct_u128)a[i] + b[i] + carry;
        o[i] = (uint64_t)v;
        carry = (uint64_t)(v >> 64);
    }
    // The sum is below 2m, and carry is its word above the k.
    reduce_once(o, o, carry, mod->m, k);
}

void rsa_mont64_sub(uint64_t *o, const uint64_t *a, const uint64_t *b,
                    const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    const uint64_t *m = mod->m;
    // a - b by the complement, as sub_masked subtracts: the carry out is
    // 1 when a is at or above b and 0 when the subtraction borrowed.
    uint64_t carry = 1;
    for (size_t i = 0; i < k; i++) {
        ct_u128 v = (ct_u128)a[i] + ~b[i] + carry;
        o[i] = (uint64_t)v;
        carry = (uint64_t)(v >> 64);
    }
    // After a borrow the words hold a - b + 2^(64k). Adding m under the
    // mask of the borrow brings them to a - b + m, and the carry out of
    // the top word, which is that 2^(64k), is dropped.
    uint64_t mask = mask_of_bit(carry ^ 1);
    carry = 0;
    for (size_t i = 0; i < k; i++) {
        ct_u128 v = (ct_u128)o[i] + (m[i] & mask) + carry;
        o[i] = (uint64_t)v;
        carry = (uint64_t)(v >> 64);
    }
}

void rsa_mont64_reduce_once(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod) {
    reduce_once(o, a, 0, mod->m, mod->words);
}

void rsa_mont64_mul_add(uint64_t *o, const uint64_t *a, const uint64_t *b, const uint64_t *c,
                        size_t k) {
    for (size_t i = 0; i < k; i++) {
        o[i] = c[i];
        o[k + i] = 0;
    }
    // Row i adds a[i] * b at word i. A product, a word of o and a carry
    // are at most 2^128 - 1 together, as in rsa_mont64_mont_mul. The word
    // of a is read through a volatile pointer at each product, for the
    // reason that function reads b[0] that way: a copy a compiler keeps
    // for the row may be in a stack slot no wipe names.
    for (size_t i = 0; i < k; i++) {
        const volatile uint64_t *a_word = &a[i];
        uint64_t carry = 0;
        for (size_t j = 0; j < k; j++) {
            ct_u128 v = ct_mul128(*a_word, b[j]) + o[i + j] + carry;
            o[i + j] = (uint64_t)v;
            carry = (uint64_t)(v >> 64);
        }
        o[i + k] = carry;
    }
}

void rsa_mont64_modulus_load(rsa_mont64_modulus *mod, const uint8_t *m, size_t m_len) {
    CH_ASSERT(m_len >= 1 && m_len <= CH_RSA_MODULUS_MAX);
    size_t k = (m_len + 7) >> 3;
    mod->words = k;
    rsa_mont64_from_bytes(mod->m, k, m, m_len);
    mod->m0inv = neg_inverse(mod->m[0]);
}

void rsa_mont64_modulus_init(rsa_mont64_modulus *mod, const uint8_t *m, size_t m_len, size_t bits) {
    CH_ASSERT(m_len >= 1 && m_len <= CH_RSA_MODULUS_MAX && bits >= 1 && bits <= 8 * m_len);
    rsa_mont64_modulus_load(mod, m, m_len);
    size_t k = mod->words;

    // r2 = R^2 mod m, with R = 2^(64k). 2^(bits - 1) is below m, because
    // m has that bit and is odd. One doubling for each power of two from
    // there up to 2^(66k) gives 2^(2k) * R mod m, the Montgomery form of
    // 2^(2k): the first 64k - (bits - 1) of them give R mod m, and the
    // last 2k the rest. Squaring that form five times raises 2^(2k) to
    // the 32nd power, which is 2^(64k) = R, and the Montgomery form of R
    // is R^2 mod m.
    power_of_two(mod->r2, k, bits - 1);
    for (size_t i = bits - 1; i < 66 * k; i++) {
        double_mod(mod->r2, mod->m, k);
    }
    for (int i = 0; i < 5; i++) {
        rsa_mont64_mont_square(mod->r2, mod->r2, mod);
    }
}

void rsa_mont64_public(uint8_t *out, const uint8_t *base, size_t len,
                       const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    CH_ASSERT(len <= 8 * k);
    // Zeroed at declaration, as rsa_mont.c's are: the words past k are
    // never read, and starting them at zero lets a reader see that
    // without following the length.
    uint64_t x[RSA_MONT64_WORDS_MAX] = {0};
    uint64_t acc[RSA_MONT64_WORDS_MAX] = {0};
    rsa_mont64_from_bytes(x, k, base, len);

    // acc holds the running power in the Montgomery domain: base * R,
    // then sixteen squarings to base^65536 * R. The last product is by
    // base itself, outside the domain, so it multiplies by base and
    // divides by R at once: base^65537. In each product the second
    // operand is below m, which is all rsa_mont64_mont_mul needs, so base
    // may be any number of k words, and each square is of a power below m.
    rsa_mont64_mont_mul(acc, x, mod->r2, mod);
    for (int i = 0; i < 16; i++) {
        rsa_mont64_mont_square(acc, acc, mod);
    }
    rsa_mont64_mont_mul(acc, x, acc, mod);
    rsa_mont64_to_bytes(out, len, acc);
    ct_wipe(x, sizeof x);
    ct_wipe(acc, sizeof acc);
}

#endif // CH_CPU_RUNTIME
