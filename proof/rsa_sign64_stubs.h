// The contracts the rsa_sign64 harnesses replace rsa_mont64.c's entries
// with, the way proof/rsa_mont64_stubs.h replaces the multiply under
// those entries.
//
// Why this exists: one signature runs thousands of Montgomery
// multiplications, each of hundreds of products, and docs/proofs.md says
// SAT cost follows the multiply count. rsa_sign64.c multiplies only
// through rsa_mont64.c, so each entry of that file it calls is a contract
// below. The #defines rename every call in rsa_sign64.c, which this
// header includes last.
//
// WHAT EACH STUB MODELS: the entry's reads and writes and nothing of its
// values. Each asserts what the real entry needs of its arguments, so a
// call that breaks one fails here, and writes any words or bytes where
// the real entry writes.
//
//   - stub_mont_mul, stub_add and stub_sub need a modulus record whose
//     word count is 1 to RSA_MONT64_WORDS_MAX and that many readable
//     words behind each operand, and write that many words of the output.
//     stub_mont_square and stub_reduce_once are the same with one operand.
//   - stub_mul_add needs k readable words behind each of its three
//     operands and writes 2k words of the output.
//   - stub_modulus_init needs a length of 1 to CH_RSA_MODULUS_MAX bytes
//     and a bit count of 1 to 8 times it, as the real entry's CH_ASSERT
//     does, and writes the record: the word count that length takes and
//     any words.
//   - stub_from_bytes needs a length that fits the word count and writes
//     that many words. stub_to_bytes needs readable words under every
//     byte it writes.
//   - stub_public needs a length the record's words hold, as the real
//     entry's CH_ASSERT does, reads that many bytes of the base and
//     writes that many of the output.
//
// WHAT DISCHARGES THE CONTRACTS: rsa_mont64_mul_harness.c and
// rsa_mont64_sums_harness.c prove the real multiplication and the real
// square in every aliasing shape rsa_sign64.c calls them in and the real
// product-and-sum,
// rsa_mont64_ops_harness.c the real sum, difference, reduction and
// marshalling, rsa_mont64_init_harness.c the real setup and
// rsa_mont64_public_harness.c the real public operation, each for any
// arguments these stubs admit.
//
// What the contracts give up: the values. No harness over them says a
// signature is the power it should be. bin/rsa_sign_equiv_test holds that
// against rsa_sign.c's ladder, the published vectors and the Wycheproof
// suite hold it against third parties, and rsa_sign64_sp1 itself checks
// every signature with the public exponent before it returns one.
//
// WHAT FOUR STUBS REMEMBER: stub_modulus_init, stub_public, stub_mul_add
// and stub_from_bytes keep the arguments of their last call and the words
// or bytes it wrote, in the variables below. The check and the key test
// compare values that live in their own locals, which a harness cannot
// name, so rsa_sign64_crt_harness.c states both over these copies: the
// check passes exactly when every byte stub_public wrote is the encoded
// message's, and the key test admits exactly when every word stub_mul_add
// wrote is a word stub_from_bytes wrote for the modulus.
#ifndef CH_RSA_SIGN64_STUBS_H
#define CH_RSA_SIGN64_STUBS_H

#include "harness.h"

#include "rsa_mont64.h"

uint64_t nondet_u64(void);

static void havoc_words(uint64_t *a, size_t k) {
    for (size_t i = 0; i < k; i++) {
        a[i] = nondet_u64();
    }
}

// The last call of each of the four stubs that remember theirs. The two
// word arrays hold twice a prime's words, which is at most one word more
// than a modulus has.
static const uint8_t *stub_init_modulus;
static size_t stub_init_len;
static const uint8_t *stub_public_base;
static size_t stub_public_len;
static uint8_t stub_public_out[CH_RSA_MODULUS_MAX];
static uint64_t stub_mul_add_out[RSA_MONT64_WORDS_MAX + 1];
static size_t stub_mul_add_words;
static uint64_t stub_from_bytes_out[RSA_MONT64_WORDS_MAX + 1];
static size_t stub_from_bytes_count;
static const uint8_t *stub_from_bytes_bytes;
static size_t stub_from_bytes_len;

// What stub_mont_mul, stub_add and stub_sub assert of a record and one
// operand.
static void need_words(const uint64_t *a, const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    __CPROVER_assert(k >= 1 && k <= RSA_MONT64_WORDS_MAX,
                     "rsa_mont64: the word count is inside the arrays");
    __CPROVER_assert(__CPROVER_r_ok(a, k * sizeof(uint64_t)),
                     "rsa_mont64: an operand holds the modulus's words");
}

static void stub_mont_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                          const rsa_mont64_modulus *mod) {
    need_words(a, mod);
    need_words(b, mod);
    havoc_words(o, mod->words);
}

static void stub_mont_square(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod) {
    need_words(a, mod);
    havoc_words(o, mod->words);
}

static void stub_add(uint64_t *o, const uint64_t *a, const uint64_t *b,
                     const rsa_mont64_modulus *mod) {
    need_words(a, mod);
    need_words(b, mod);
    havoc_words(o, mod->words);
}

static void stub_sub(uint64_t *o, const uint64_t *a, const uint64_t *b,
                     const rsa_mont64_modulus *mod) {
    need_words(a, mod);
    need_words(b, mod);
    havoc_words(o, mod->words);
}

static void stub_reduce_once(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *mod) {
    need_words(a, mod);
    havoc_words(o, mod->words);
}

static void stub_mul_add(uint64_t *o, const uint64_t *a, const uint64_t *b, const uint64_t *c,
                         size_t k) {
    __CPROVER_assert(__CPROVER_r_ok(a, k * sizeof(uint64_t)),
                     "rsa_mont64_mul_add: a holds k words");
    __CPROVER_assert(__CPROVER_r_ok(b, k * sizeof(uint64_t)),
                     "rsa_mont64_mul_add: b holds k words");
    __CPROVER_assert(__CPROVER_r_ok(c, k * sizeof(uint64_t)),
                     "rsa_mont64_mul_add: c holds k words");
    __CPROVER_assert(2 * k <= RSA_MONT64_WORDS_MAX + 1,
                     "rsa_mont64_mul_add: the product is at most twice a prime's words");
    havoc_words(o, 2 * k);
    stub_mul_add_words = k;
    for (size_t i = 0; i < 2 * k; i++) {
        stub_mul_add_out[i] = o[i];
    }
}

static void stub_modulus_init(rsa_mont64_modulus *mod, const uint8_t *m, size_t m_len,
                              size_t bits) {
    __CPROVER_assert(m_len >= 1 && m_len <= CH_RSA_MODULUS_MAX && bits >= 1 && bits <= 8 * m_len,
                     "rsa_mont64_modulus_init: the lengths its CH_ASSERT admits");
    __CPROVER_assert(__CPROVER_r_ok(m, m_len), "rsa_mont64_modulus_init: the modulus is readable");
    mod->words = (m_len + 7) >> 3;
    havoc_words(mod->m, mod->words);
    havoc_words(mod->r2, mod->words);
    mod->m0inv = nondet_u64();
    stub_init_modulus = m;
    stub_init_len = m_len;
}

static void stub_from_bytes(uint64_t *words, size_t count, const uint8_t *bytes, size_t len) {
    __CPROVER_assert(len <= 8 * count, "rsa_mont64_from_bytes: the bytes fit the words");
    __CPROVER_assert(len == 0 || __CPROVER_r_ok(bytes, len),
                     "rsa_mont64_from_bytes: the bytes are readable");
    __CPROVER_assert(count <= RSA_MONT64_WORDS_MAX + 1,
                     "rsa_mont64_from_bytes: at most twice a prime's words");
    havoc_words(words, count);
    stub_from_bytes_count = count;
    stub_from_bytes_bytes = bytes;
    stub_from_bytes_len = len;
    for (size_t i = 0; i < count; i++) {
        stub_from_bytes_out[i] = words[i];
    }
}

static void stub_to_bytes(uint8_t *bytes, size_t len, const uint64_t *words) {
    __CPROVER_assert(len == 0 || __CPROVER_r_ok(words, ((len + 7) >> 3) * sizeof(uint64_t)),
                     "rsa_mont64_to_bytes: a word is readable under every byte");
    for (size_t i = 0; i < len; i++) {
        bytes[i] = nondet_u8();
    }
}

static void stub_public(uint8_t *out, const uint8_t *base, size_t len,
                        const rsa_mont64_modulus *mod) {
    __CPROVER_assert(mod->words >= 1 && mod->words <= RSA_MONT64_WORDS_MAX && len <= 8 * mod->words,
                     "rsa_mont64_public: the length its CH_ASSERT admits");
    __CPROVER_assert(len == 0 || __CPROVER_r_ok(base, len),
                     "rsa_mont64_public: the base is readable");
    stub_public_base = base;
    stub_public_len = len;
    for (size_t i = 0; i < len; i++) {
        out[i] = nondet_u8();
        stub_public_out[i] = out[i];
    }
}

// From here on rsa_sign64.c's calls into rsa_mont64.c are the contracts
// above.
#define rsa_mont64_mont_mul stub_mont_mul
#define rsa_mont64_mont_square stub_mont_square
#define rsa_mont64_add stub_add
#define rsa_mont64_sub stub_sub
#define rsa_mont64_reduce_once stub_reduce_once
#define rsa_mont64_mul_add stub_mul_add
#define rsa_mont64_modulus_init stub_modulus_init
#define rsa_mont64_from_bytes stub_from_bytes
#define rsa_mont64_to_bytes stub_to_bytes
#define rsa_mont64_public stub_public

#include "rsa_sign64.c"

#endif
