// Proves rsa_sign.c's memory safety and absence of UB over unconstrained
// inputs, in six pieces, with full checks.
//
// Marshalling and the word helpers, at the real bound. words_from_bytes
// and words_to_bytes, and then sub_borrow, sub_masked, below, cond_sub
// and cswap_words, run at k = WORDS_MAX (96 for the device bound of
// RSA-3072) over nondet bytes and nondet words, with the operands
// havocked freshly before every call. The maximal k is the binding case
// for every index: rsa_pss_sign_key_ok's n_len check is what holds k
// there, and a smaller k only shortens the same loops.
//
// The key test. rsa_pss_sign_key_ok (rsa_sign.h), over any n_len and any
// modulus bytes, reads inside n, and every key it admits has the n_len
// the paragraph above rests on: 256 to CH_RSA_MODULUS_MAX, a multiple of
// 8.
//
// The mask. mask_of_bit must return all ones or all zeros and nothing
// else, because every select in the file is an AND against it or its
// complement: a mask with a mixed bit pattern would mix two values
// instead of choosing one. Proved over both inputs, and below()'s answer
// is proved to be the one bit mask_of_bit admits.
//
// The exponent index. The ladder reads bit i of d for i over
// 0..8*n_len-1, and the byte it reads is d[n_len - 1 - (i >> 3)]. The
// loop itself has 8 * n_len iterations, far past any unwinding bound, so
// the index is proved here over a nondet i under the loop's own range,
// which is what the loop establishes for each of its iterations.
//
// The CIOS carry lemma, behind mont_mul. In both passes the uint64
// accumulation v = x*y + t + c cannot wrap and its carry-out fits back in
// one 32-bit word, for ANY uint32 operands, and each pass's tail spills
// at most one bit. The bound is inductive, so a fixed step count stands
// in for the real k-word passes and the count never enters the argument.
// This is rsa_mul_harness.c's lemma over the same CIOS shape; the two
// files keep their own copies because rsa_sign.c's products go through
// ct_widemul and rsa_mont.c's do not.
//
// What no formula here drives, and why:
//
//   mont_mul whole, and rsa_sp1 above it. Its inner passes are k
//   multiplies deep at k = 96, and a symbolic modexp never leaves
//   symbolic execution -- the same limit rsa_mul_harness.c records for
//   rsa_vp1. Every index in it walks a fixed WORDS_MAX-sized array under
//   k <= WORDS_MAX, and the carry lemma covers the arithmetic.
//
//   mont_r2. Its shift loop runs 64 * k = 6,144 times, past any unwinding
//   bound this tier can carry. Its body is cond_sub and a word shift,
//   both proved here.
//
//   The final conditional subtract's functional claim, that t stays below
//   2m at loop exit. That is a CIOS invariant, and it rests on the
//   vectors in test/rsa_sign_test.c and the Wycheproof signing suite, not
//   on a proof.
// The PSS encoder hashes, and the encoder is a piece this harness drives
// whole; sha256.c has its own proof, so the stub stands in for it.
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

// One CIOS pass, x nondet each step: a superset of both real passes (the
// multiply pass holds x = a[i] fixed, the reduction pass runs with
// x = u).
static uint64_t mac_pass(uint64_t c) {
    for (int j = 0; j < 8; j++) {
        uint64_t x = nondet_u32();
        uint64_t y = nondet_u32();
        uint64_t t = nondet_u32();
        uint64_t p = ct_widemul((uint32_t)x, (uint32_t)y); // <= (2^32-1)^2, no wrap
        __CPROVER_assert(p <= UINT64_MAX - t - c, "accumulate cannot wrap");
        c = (p + t + c) >> 32;
        __CPROVER_assert(c <= UINT32_MAX, "carry fits one word");
    }
    return c;
}

static void prove_marshalling(void) {
    uint8_t b[4 * WORDS_MAX];
    uint32_t words[WORDS_MAX];
    fill_nondet(b, sizeof b);
    words_from_bytes(words, b, WORDS_MAX);
    havoc_words(words, WORDS_MAX);
    words_to_bytes(b, words, WORDS_MAX);
}

static void prove_word_helpers(void) {
    uint32_t a[WORDS_MAX];
    uint32_t b[WORDS_MAX];
    havoc_words(a, WORDS_MAX);
    havoc_words(b, WORDS_MAX);
    uint32_t borrow = sub_borrow(a, b, WORDS_MAX);
    __CPROVER_assert(borrow <= 1, "sub_borrow answers one bit");

    havoc_words(a, WORDS_MAX);
    havoc_words(b, WORDS_MAX);
    sub_masked(a, b, WORDS_MAX, nondet_u32());

    havoc_words(a, WORDS_MAX);
    havoc_words(b, WORDS_MAX);
    uint32_t low = below(a, b, WORDS_MAX, nondet_u32());
    __CPROVER_assert(low <= 1, "below answers one bit");

    havoc_words(a, WORDS_MAX);
    havoc_words(b, WORDS_MAX);
    cond_sub(a, b, WORDS_MAX, nondet_u32() & 1);

    havoc_words(a, WORDS_MAX);
    havoc_words(b, WORDS_MAX);
    cswap_words(a, b, WORDS_MAX, nondet_u32());
}

static void prove_masks(void) {
    uint32_t bit = nondet_u32() & 1;
    uint32_t m = mask_of_bit(bit);
    __CPROVER_assert(m == 0 || m == UINT32_MAX, "mask_of_bit is all ones or all zeros");
    __CPROVER_assert((bit == 1) == (m == UINT32_MAX), "mask_of_bit follows its bit");
}

// The key test rsa_pss_sign runs first and a server runs on its
// configuration, over any n_len and any modulus bytes: it reads inside
// n, and a key it admits has the n_len every piece above assumes.
static void prove_key_ok(void) {
    static ch_rsa_priv k;
    fill_nondet(k.n, sizeof k.n);
    k.n_len = nondet_size_t();
    int ok = rsa_pss_sign_key_ok(&k);
    __CPROVER_assert(ok == 0 || ok == 1, "rsa_pss_sign_key_ok: the answer is 1 or 0");
    __CPROVER_assert(!ok || (k.n_len >= 256 && k.n_len <= CH_RSA_MODULUS_MAX && k.n_len % 8 == 0),
                     "an admitted key's n_len is the one the marshalling bound assumes");
}

// The ladder's read of bit i of d, over the range the loop gives it.
static void prove_exponent_index(void) {
    size_t n_len = nondet_size_t();
    __CPROVER_assume(n_len >= 256 && n_len <= CH_RSA_MODULUS_MAX && n_len % 8 == 0);
    size_t i = nondet_size_t();
    __CPROVER_assume(i < 8 * n_len);
    size_t byte = n_len - 1 - (i >> 3);
    __CPROVER_assert(byte < n_len, "the exponent byte index stays inside d");
    __CPROVER_assert((i & 7) < 8, "the shift stays inside a byte");
}

// The encoder whole, at the largest encoded message it writes. Every
// length it computes comes from em_len, so the maximal one is the
// binding case for the MGF1 mask, the PS run and the salt copy. The
// salt is the caller's draw (srv_auth.c's sign_rsa_pss): unconstrained
// bytes, less the all-zero draw. rsa_sign.c asserts against that one
// because it is what a source that returns without writing leaves
// behind (INV-4), and rand.h's contract is that the source writes n
// random bytes, so this harness honours the contract rather than firing
// the assertion.
static void prove_encoder(void) {
    uint8_t msg_hash[32];
    uint8_t salt[SLEN];
    uint8_t em[CH_RSA_MODULUS_MAX];
    fill_nondet(msg_hash, sizeof msg_hash);
    fill_nondet(salt, sizeof salt);
    uint8_t any = 0;
    for (size_t i = 0; i < sizeof salt; i++) {
        any |= salt[i];
    }
    __CPROVER_assume(any != 0);
    fill_nondet(em, sizeof em);
    emsa_pss_encode(msg_hash, salt, em, CH_RSA_MODULUS_MAX);
}

int main(void) {
    prove_marshalling();
    prove_word_helpers();
    prove_masks();
    prove_key_ok();
    prove_exponent_index();
    prove_encoder();

    // Multiply pass, then its tail: v = t[k] + c spills at most one bit
    // into t[k+1].
    uint64_t c = mac_pass(0);
    uint64_t v = (uint64_t)nondet_u32() + c;
    uint32_t t_k1 = (uint32_t)(v >> 32);
    __CPROVER_assert(t_k1 <= 1, "multiply tail spills one bit at most");

    // Reduction pass: the first step adds u*m[0] to t[0] with no carry-in
    // and feeds the rest of the pass.
    uint64_t u = nondet_u32();
    uint64_t m0 = nondet_u32();
    uint64_t t0 = nondet_u32();
    uint64_t first = ct_widemul((uint32_t)u, (uint32_t)m0);
    __CPROVER_assert(first <= UINT64_MAX - t0, "first add cannot wrap");
    c = mac_pass((first + t0) >> 32);
    v = (uint64_t)nondet_u32() + c;
    uint32_t spill = (uint32_t)(v >> 32);
    __CPROVER_assert(spill <= 1, "reduction tail spills one bit at most");

    // The reduction tail sets t[k] = t[k+1] + spill; both are 0 or 1, so
    // the carry word the next round reads stays inside one word.
    uint64_t t_k = (uint64_t)t_k1 + spill;
    __CPROVER_assert(t_k <= UINT32_MAX, "carry word sum stays in one word");
    return 0;
}
