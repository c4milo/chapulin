// Proves: rsa_mont64_public_exp (rsa_mont64_exp.c), over any modulus
// word count, any length its contract admits and any odd exponent of 3 to
// 64 bits, reads and writes inside its arrays and hands each Montgomery
// call k words. Under RSA_MONT64_EXP_SCHEDULE, which
// proof/rsa_mont64_exp_schedule_harness.c sets, it proves the schedule of
// the exponent instead: one squaring for each bit below the top bit, and
// one product for each set bit. That line holds the exponent below 2^32,
// 3 and 65537 among them, and the modulus at one word: over every 64-bit
// exponent the counts gave no verdict in 20 minutes, and at 32 bits they
// take about 40 seconds.
//
// rsa_mont64.c's calls are contract stubs here. Each asserts the words it
// reads and writes, and writes nothing: no property reads a word's value,
// and writing 48 words at each of 126 calls kept the solver past 20
// minutes. rsa_mont64.c's own harnesses prove the real calls. A product at RSA-3072 runs 4,656
// multiplies, and this loop makes up to 126 of them, a formula docs/proofs.md says not to build.
// The stubs count the calls, which is how the schedule is read.
//
// What it does not prove: that the bytes are base^e mod m.
// bin/rsa_exp_test holds that against Python's pow and against
// rsa_mont64_public at 65537.
#include "harness.h"

#include "rsa_mont64.h"

uint64_t nondet_u64(void);

static rsa_mont64_modulus mod;
static int products;
static int squares;

// The k words a call reads or writes, k being the modulus's.
static int words_ok(const uint64_t *p) {
    return __CPROVER_w_ok(p, mod.words * sizeof(uint64_t));
}

void rsa_mont64_from_bytes(uint64_t *words, size_t count, const uint8_t *bytes, size_t len) {
    __CPROVER_assert(count == mod.words && __CPROVER_w_ok(words, count * sizeof(uint64_t)),
                     "from_bytes: k words writable");
    __CPROVER_assert(len <= 8 * count && (len == 0 || __CPROVER_r_ok(bytes, len)),
                     "from_bytes: the bytes fit and are readable");
}

void rsa_mont64_to_bytes(uint8_t *bytes, size_t len, const uint64_t *words) {
    __CPROVER_assert(len == 0 || __CPROVER_w_ok(bytes, len), "to_bytes: output writable");
    __CPROVER_assert(len <= 8 * mod.words && words_ok(words), "to_bytes: the words are readable");
}

void rsa_mont64_mont_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                         const rsa_mont64_modulus *m) {
    __CPROVER_assert(m == &mod && words_ok(o) && words_ok(a) && words_ok(b),
                     "mont_mul: k words each");
    products++;
}

void rsa_mont64_mont_square(uint64_t *o, const uint64_t *a, const rsa_mont64_modulus *m) {
    __CPROVER_assert(m == &mod && words_ok(o) && words_ok(a), "mont_square: k words each");
    squares++;
}

int main(void) {
    size_t words = nondet_size_t();
#ifdef RSA_MONT64_EXP_SCHEDULE
    __CPROVER_assume(words == 1);
#else
    __CPROVER_assume(words >= 1 && words <= RSA_MONT64_WORDS_MAX);
#endif
    mod.words = words;
    uint8_t base[CH_RSA_MODULUS_MAX];
    uint8_t out[CH_RSA_MODULUS_MAX];
    fill_nondet(base, sizeof base);
    size_t len = nondet_size_t();
    __CPROVER_assume(len <= 8 * words);
    uint64_t e = nondet_u64();
    __CPROVER_assume(e >= 3 && (e & 1) == 1);
#ifdef RSA_MONT64_EXP_SCHEDULE
    __CPROVER_assume(e < ((uint64_t)1 << 32));
#endif

    rsa_mont64_public_exp(out, base, len, &mod, e);

#ifdef RSA_MONT64_EXP_SCHEDULE
    int bits = 0;
    int set = 0;
    for (uint64_t v = e; v != 0; v >>= 1) {
        bits++;
        set += (int)(v & 1);
    }
    __CPROVER_assert(squares == bits - 1, "one squaring for each bit below the top");
    __CPROVER_assert(products == set, "one product for each set bit");
#endif
    return 0;
}
