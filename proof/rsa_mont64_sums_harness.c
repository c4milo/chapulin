// Proves: no sum in rsa_mont64_mont_mul or rsa_mont64_mont_square wraps,
// for any operands, any modulus and any m0inv. The check is
// --unsigned-overflow-check on the launch line, which makes every unsigned
// +, - and * a property: each sum of a product, a word of the running sum
// and a carry; the sum of the two carries with the running sum's top word;
// and every word of the last subtraction, which adds a complement where a
// borrow would wrap.
//
// The products are the contract in proof/rsa_mont64_stubs.h: any value at
// or below (2^64 - 1)^2, which rsa_mont64_mul128_harness.c proves of the
// real multiply. Under it the bound is the one rsa_mont64.c's header
// states: a product and two words are at most 2^128 - 1.
//
// It runs the shipped function at four words, not at the build's 48 or
// 64. Four words run every statement in every position it has: the first
// round over a zeroed sum and three rounds over a sum the round before
// wrote, the first word of a round and three words after it, the top
// step, and the last subtraction. Each sum reads one product, one word
// and one or two carries, and every one of those is an unconstrained
// 64-bit value or a value the function itself computed from such values,
// so the word count is no part of the argument: more words repeat the
// same sums over the same ranges. The whole function at 48 words with
// this check on returned no verdict in five minutes and 8.5 GB;
// rsa_mont64_mul_harness.c runs it there for its memory accesses.
//
// The four calls are the aliasing shapes rsa_mont64_mul_harness.c names.
//
// rsa_mont64_mont_square runs at four words too, in its two shapes. Four
// words run each of its rows: row 0, whose square comes before its u; a
// row whose part below the square is empty; rows with words past the
// square and past the word above it; and the last row, which has neither.
// Each of its sums is at most a product and two words, and the running
// sum's top word, which reaches 2 in a square where a multiplication's
// reaches 1, stays at most 3 under any products the contract gives.
//
// rsa_mont64_mul_add, the plain product and sum, runs the same sum of a
// product, a word and a carry, so one call at four words holds it to the
// same bound.
#include "rsa_mont64_stubs.h"

#define SUMS_WORDS 4

int main(void) {
    rsa_mont64_modulus mod;
    uint64_t a[RSA_MONT64_WORDS_MAX];
    uint64_t b[RSA_MONT64_WORDS_MAX];
    uint64_t o[RSA_MONT64_WORDS_MAX];

    havoc_modulus(&mod, SUMS_WORDS);
    havoc_words(a, SUMS_WORDS);
    havoc_words(b, SUMS_WORDS);
    rsa_mont64_mont_mul(o, a, b, &mod);

    havoc_modulus(&mod, SUMS_WORDS);
    havoc_words(a, SUMS_WORDS);
    havoc_words(b, SUMS_WORDS);
    rsa_mont64_mont_mul(b, a, b, &mod);

    havoc_modulus(&mod, SUMS_WORDS);
    havoc_words(a, SUMS_WORDS);
    havoc_words(b, SUMS_WORDS);
    rsa_mont64_mont_mul(a, a, b, &mod);

    havoc_modulus(&mod, SUMS_WORDS);
    havoc_words(a, SUMS_WORDS);
    rsa_mont64_mont_mul(a, a, a, &mod);

    havoc_modulus(&mod, SUMS_WORDS);
    havoc_words(a, SUMS_WORDS);
    rsa_mont64_mont_square(o, a, &mod);

    havoc_modulus(&mod, SUMS_WORDS);
    havoc_words(a, SUMS_WORDS);
    rsa_mont64_mont_square(a, a, &mod);

    uint64_t product[2 * SUMS_WORDS];
    havoc_words(a, SUMS_WORDS);
    havoc_words(b, SUMS_WORDS);
    havoc_words(o, SUMS_WORDS);
    rsa_mont64_mul_add(product, a, b, o, SUMS_WORDS);
    return 0;
}
