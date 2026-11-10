// Proves: rsa_vp1 as a host object compiles it (rsa_mont.c under
// -DCH_CPU_RUNTIME), whole, over any odd modulus bytes and any signature
// bytes at the largest length the build admits (384 bytes; 512 in the
// rsa_mont_host_webpki variant, which sets CH_TRUST_WEBPKI), reads and
// writes inside its arrays and divides by no zero. A modulus whose top
// bit is set takes public_by_division (docs/decisions.md 208):
// rsa_mont64_modulus_load, the base's words and its one subtraction, and
// the k steps of the division that multiplies the base by R, each with
// its quotient estimate, its subtraction and its passes that add the
// modulus back. Any other modulus takes rsa_mont64_modulus_init, under
// every bit length the bytes give it.
//
// The steps here are times_word_mod's loops. rsa_mont_host_blocks runs
// this file with RSA_MONT64_BLOCKS set to 1, where a word count that is a
// multiple of 4 takes times_word_mod_blocks. There rsa_mont64_block_add
// is a contract too: it writes any four words to the four it is given and
// returns any word. rsa_mont_division_sums proves the real block's sums
// for every input, so this formula holds none of them.
//
// The products are the contract in proof/rsa_mont64_stubs.h, which
// rsa_mont64_mul128_harness.c discharges on the real multiply. The four
// entries below whose own harnesses prove them are contracts that assert
// what the real entry needs and write where it writes:
// rsa_mont64_modulus_init (rsa_mont64_init_harness.c), rsa_mont64_public
// (rsa_mont64_public_harness.c), and rsa_mont64_mont_square and
// rsa_mont64_mont_mul (rsa_mont64_mul_harness.c, and
// rsa_mont64_blocks_harness.c for the blocks), in the two shapes
// public_by_division calls them in: a square in place, and a product
// whose output is its second operand. The modulus is odd because rsa.h
// admits no other: both verifiers refuse an even one or a zero one before
// they call rsa_vp1.
//
// This line runs without --unsigned-overflow-check: the word above the
// k in a step of the division wraps to zero on purpose when a pass adds
// the modulus back.
//
// What it does not prove: that the words the division writes are the
// base times R mod m. spec/lean/Spec/RsaDivision.lean proves that on a
// model of the C, bin/diff_rsa_division holds the C to the model, and
// bin/rsa_equiv_test holds the bytes against rsa_mont.c's 32-bit
// arithmetic over random moduli and moduli of every bit length near a
// word boundary.
#include "rsa_mont64_stubs.h"

static void stub_modulus_init(rsa_mont64_modulus *mod, const uint8_t *m, size_t m_len,
                              size_t bits) {
    __CPROVER_assert(m_len >= 1 && m_len <= CH_RSA_MODULUS_MAX && bits >= 1 && bits <= 8 * m_len,
                     "rsa_mont64_modulus_init: the lengths its CH_ASSERT admits");
    __CPROVER_assert(__CPROVER_r_ok(m, m_len), "rsa_mont64_modulus_init: the modulus is readable");
    havoc_modulus(mod, (m_len + 7) >> 3);
}

static void stub_public(uint8_t *out, const uint8_t *base, size_t len,
                        const rsa_mont64_modulus *mod) {
    __CPROVER_assert(mod->words >= 1 && mod->words <= RSA_MONT64_WORDS_MAX,
                     "rsa_mont64_public: the word count is inside the arrays");
    __CPROVER_assert(len <= 8 * mod->words, "rsa_mont64_public: the length its CH_ASSERT admits");
    __CPROVER_assert(__CPROVER_r_ok(base, len), "rsa_mont64_public: the base is readable");
    __CPROVER_assert(__CPROVER_w_ok(out, len), "rsa_mont64_public: the output is writable");
    fill_nondet(out, len);
}

static void stub_mont_square(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    __CPROVER_assert(k >= 1 && k <= RSA_MONT64_WORDS_MAX,
                     "rsa_mont64_mont_square: the word count is inside the arrays");
    __CPROVER_assert(__CPROVER_r_ok(a, k * sizeof(uint64_t)),
                     "rsa_mont64_mont_square: the operand is readable");
    __CPROVER_assert(__CPROVER_w_ok(o, k * sizeof(uint64_t)),
                     "rsa_mont64_mont_square: the output is writable");
    havoc_words(o, k);
}

static void stub_mont_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                          const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    __CPROVER_assert(k >= 1 && k <= RSA_MONT64_WORDS_MAX,
                     "rsa_mont64_mont_mul: the word count is inside the arrays");
    __CPROVER_assert(__CPROVER_r_ok(a, k * sizeof(uint64_t)),
                     "rsa_mont64_mont_mul: the first operand is readable");
    __CPROVER_assert(__CPROVER_r_ok(b, k * sizeof(uint64_t)),
                     "rsa_mont64_mont_mul: the second operand is readable");
    __CPROVER_assert(__CPROVER_w_ok(o, k * sizeof(uint64_t)),
                     "rsa_mont64_mont_mul: the output is writable");
    havoc_words(o, k);
}

#if RSA_MONT64_BLOCKS
static uint64_t stub_block_add(uint64_t t[4], uint64_t x, uint64_t y0, uint64_t y1, uint64_t y2,
                               uint64_t y3, uint64_t w) {
    (void)x;
    (void)y0;
    (void)y1;
    (void)y2;
    (void)y3;
    (void)w;
    // Each store is a property of its own: the four words are inside
    // their array. A predicate over the pointer in their place made each of
    // the division's 576 blocks an object of the formula, past the 256
    // that cbmc numbers.
    t[0] = nondet_u64();
    t[1] = nondet_u64();
    t[2] = nondet_u64();
    t[3] = nondet_u64();
    return nondet_u64();
}
#define rsa_mont64_block_add stub_block_add
#endif

#define rsa_mont64_modulus_init stub_modulus_init
#define rsa_mont64_public stub_public
#define rsa_mont64_mont_square stub_mont_square
#define rsa_mont64_mont_mul stub_mont_mul
#include "rsa_mont.c"

int main(void) {
    uint8_t n[CH_RSA_MODULUS_MAX];
    uint8_t sig[CH_RSA_MODULUS_MAX];
    uint8_t em[CH_RSA_MODULUS_MAX];
    fill_nondet(n, sizeof n);
    fill_nondet(sig, sizeof sig);
    __CPROVER_assume((n[sizeof n - 1] & 1) == 1);
    rsa_vp1(n, sizeof n, sig, em);
    return 0;
}
