// Proves rsa_sign.c's exponent blinding (docs/decisions.md 186) in three
// pieces, with full checks.
//
// The two word helpers, add_masked and shift_left_one, at k =
// EXPONENT_WORDS_MAX, over nondet words and a nondet mask: memory safety
// at the real bound, with the operands havocked freshly before each call.
//
// blinded_exponent at words = WORDS_MAX, the largest modulus, over nondet
// d bytes and a nondet blind: memory safety and no undefined behavior
// across its six loops and its 64 passes.
//
// The value, by its steps at one word: scale_minus_one writes 65537 d - 1,
// and blind_pass writes 2 exponent + bit t, each checked against 64-bit
// or 128-bit arithmetic. Both are linear, so the formula holds no
// multiplier to compare with the passes. spec/lean/Spec/RsaBlind.lean
// proves that 64 passes over r's bits write r t (passes_eq), and that the
// exponent gives m^d mod n (blinded_pow_mod). The steps are the same code
// at every word count, so one word holds the arithmetic and the bound
// above holds the indices.
#define CH_PROOF_STUB_SHA256
#include "harness.h"

#include <stdint.h>

#include "sha256.h"

uint32_t nondet_u32(void);

#include "rsa_sign.c"

static void havoc_words(uint32_t *a, size_t k) {
    for (size_t i = 0; i < k; i++) {
        a[i] = nondet_u32();
    }
}

static void prove_helpers(void) {
    uint32_t a[EXPONENT_WORDS_MAX];
    uint32_t b[EXPONENT_WORDS_MAX];
    havoc_words(a, EXPONENT_WORDS_MAX);
    havoc_words(b, EXPONENT_WORDS_MAX);
    add_masked(a, b, EXPONENT_WORDS_MAX, nondet_u32());
    havoc_words(a, EXPONENT_WORDS_MAX);
    shift_left_one(a, EXPONENT_WORDS_MAX);
}

static void prove_bounds(void) {
    uint8_t d[CH_RSA_MODULUS_MAX];
    uint8_t blind[RSA_BLIND_LEN];
    uint32_t exponent[EXPONENT_WORDS_MAX];
    fill_nondet(d, sizeof d);
    fill_nondet(blind, sizeof blind);
    blinded_exponent(exponent, d, WORDS_MAX, blind);
}

// scale_minus_one at one word: t = 65537 d - 1 over two words, for every
// d of 1 or more.
static void prove_scale(void) {
    uint32_t t[2];
    uint32_t d = nondet_u32();
    __CPROVER_assume(d >= 1);
    t[0] = d;
    t[1] = 0;
    scale_minus_one(t, 1);
    uint64_t want = (uint64_t)d * 65537 - 1;
    __CPROVER_assert(t[0] == (uint32_t)want && t[1] == (uint32_t)(want >> 32),
                     "scale_minus_one writes 65537 d - 1");
}

// blind_pass at four words, the size of one word's exponent: exponent' = 2
// exponent + bit t, for every exponent below 2^127, every t below 2^96 and
// either bit. The 64 passes compose to r t (spec/lean/Spec/RsaBlind.lean,
// passes_eq).
static void prove_pass(void) {
    uint32_t exponent[1 + BLIND_WORDS];
    uint32_t t[1 + BLIND_WORDS];
    havoc_words(exponent, 1 + BLIND_WORDS);
    havoc_words(t, 1 + BLIND_WORDS);
    __CPROVER_assume(exponent[3] < 0x80000000U && t[3] == 0);
    uint32_t bit = nondet_u32() & 1;
    uint32_t mask = mask_of_bit(bit);
    unsigned __int128 before = 0;
    unsigned __int128 addend = 0;
    for (size_t i = 1 + BLIND_WORDS; i-- > 0;) {
        before = (before << 32) | exponent[i];
        addend = (addend << 32) | t[i];
    }
    blind_pass(exponent, t, 1 + BLIND_WORDS, mask);
    unsigned __int128 want = 2 * before + (bit ? addend : 0);
    for (size_t i = 0; i < 1 + BLIND_WORDS; i++) {
        __CPROVER_assert(exponent[i] == (uint32_t)(want >> (32 * i)),
                         "blind_pass writes 2 exponent + bit t");
    }
}

int main(void) {
    prove_helpers();
    prove_bounds();
    prove_scale();
    prove_pass();
    return 0;
}
