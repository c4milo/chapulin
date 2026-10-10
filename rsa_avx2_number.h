// A number in rsa_avx2.c's layout, and the conversions between it and
// rsa_mont64.c's words. A number is an array of NUMBER_LANES words: PAD
// lanes of zeros, its n digits of D bits, digit j at lane PAD + j, and
// zeros above them. The modulus's record holds m as such a number, with
// what each product reads beside it.
//
// Only rsa_avx2.c includes this file, after the attribute push that turns
// AVX2 on, so its functions carry that target as the kernel's do. Nothing
// here is an AVX2 instruction. Every branch and every memory index
// depends on a count or an index alone, as in the rest of the kernel.
#ifndef CH_RSA_AVX2_NUMBER_H
#define CH_RSA_AVX2_NUMBER_H

#include "rsa_avx2.h"

#if defined(CH_CPU_RUNTIME) && (defined(__x86_64__) || defined(CH_RSA_AVX2_MODEL))

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "rsa_mont64.h"

// The zero lanes below a number's digit 0, as many as a view moves down.
#define PAD ((size_t)4)
// The most groups of four digits a number takes: 28 at the 384-byte bound
// and 38 at the 512-byte one.
#define GROUPS_MAX (((size_t)RSA_AVX2_DIGIT_COUNT(RSA_MONT64_WORDS_MAX) + 3) / 4)
// A number's lanes: the views of registers 0 to GROUPS_MAX read up to lane
// PAD + 4 * GROUPS_MAX + 3.
#define NUMBER_LANES ((size_t)4 * (GROUPS_MAX + 2))

// What each product reads of the modulus. rsa_avx2_public writes it on
// its own stack at the start of each call, from rsa_mont64.c's record of
// the same modulus. No session stores it, and it holds nothing secret.
typedef struct {
    _Alignas(32) uint64_t digits[NUMBER_LANES]; // m, as a number
    uint64_t k0;                                // -m^-1 mod 2^D
    size_t digit_count;                         // n = rsa_avx2_digit_count(k)
    size_t groups;                              // ceil(n / 4)
    unsigned bits;                              // D
} rsa_avx2_modulus;

// values[index] for an index below count, and 0 from count up. The index
// is public.
static uint64_t value_at_or_zero(const uint64_t *values, size_t count, size_t index) {
    return index < count ? values[index] : 0;
}

// number = the word_count-word value at words, which must be below
// 2^(bits * digit_count), as a number: digit j is bits bits * j to
// bits * j + bits - 1 of the value. They start at bit offset of word
// bits * j / 64 and run into the next word when offset is above 64 - bits.
// The next word's shift left by 64 - offset is two shifts, so that an
// offset of 0 shifts that word out whole, where one shift by 64 would be
// undefined.
static void words_to_digits(uint64_t *number, const uint64_t *words, size_t word_count,
                            size_t digit_count, unsigned bits) {
    uint64_t mask = ((uint64_t)1 << bits) - 1;
    memset(number, 0, NUMBER_LANES * sizeof(uint64_t));
    for (size_t j = 0; j < digit_count; j++) {
        size_t bit = (size_t)bits * j;
        size_t index = bit / 64;
        unsigned offset = (unsigned)(bit % 64);
        uint64_t low = value_at_or_zero(words, word_count, index) >> offset;
        uint64_t high = value_at_or_zero(words, word_count, index + 1) << (63 - offset) << 1;
        number[PAD + j] = (low | high) & mask;
    }
}

// words[0..word_count] = the value of the number, each digit below 2^bits:
// word_count words and the word above them, which must hold the whole
// value. Digit j starts at bit offset of word bits * j / 64, and its bits
// above 64 - offset run into the next word, which takes the digit shifted
// right by 64 - offset in two shifts, as words_to_digits shifts left. The
// words are written in order of the digits, so no index or shift comes
// from a division by the digit width.
static void digits_to_words(uint64_t *words, size_t word_count, const uint64_t *number,
                            size_t digit_count, unsigned bits) {
    memset(words, 0, (word_count + 1) * sizeof(uint64_t));
    for (size_t j = 0; j < digit_count; j++) {
        size_t bit = (size_t)bits * j;
        size_t index = bit / 64;
        unsigned offset = (unsigned)(bit % 64);
        uint64_t digit = number[PAD + j];
        if (index <= word_count) {
            words[index] |= digit << offset;
        }
        if (offset + bits > 64 && index + 1 <= word_count) {
            words[index + 1] |= digit >> (63 - offset) >> 1;
        }
    }
}

// The product's record of mod's modulus: its digits, the low bits bits of
// rsa_mont64.c's -m^-1 mod 2^64, which are -m^-1 mod 2^bits, and the digit
// and group counts for its k words.
static void modulus_from_words(rsa_avx2_modulus *modulus, const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    modulus->bits = RSA_AVX2_DIGIT_BITS(k);
    modulus->digit_count = rsa_avx2_digit_count(k);
    modulus->groups = (modulus->digit_count + 3) / 4;
    modulus->k0 = mod->m0inv & (((uint64_t)1 << modulus->bits) - 1);
    words_to_digits(modulus->digits, mod->m, k, modulus->digit_count, modulus->bits);
}

#endif // CH_CPU_RUNTIME && (__x86_64__ || CH_RSA_AVX2_MODEL)

#endif
