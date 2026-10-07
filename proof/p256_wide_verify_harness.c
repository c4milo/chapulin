// Proves, for p256_wide_verify.c, the whole of p256_wide_verify_rs over
// an unconstrained key, hash, r and s:
//
//   memory safety and absence of UB;
//
//   that it answers 0 or 1;
//
//   that it answers 0 for an r or an s outside 1..n-1, and calls no entry
//   of the wide files for one;
//
//   that it answers 0 for a key the decoder refuses, and for a sum at
//   infinity, and asks for no x of a sum at infinity. No test can hold the
//   first: with the check gone, the arithmetic after it runs on words that
//   are no point, and its x matches r one time in 2^256;
//
//   that it answers 1 only after the decoder took the key, the sum was
//   finite and its x was r modulo n;
//
//   that the bytes it hands the decoder start with 0x04, the leading byte
//   of the one encoding the decoder reads;
//
//   that every scalar it hands p256_wide_scalar_inverse,
//   p256_wide_scalar_mul and p256_wide_jacobian_double_mul is below n,
//   which is what their contract takes, and that the r it compares is in
//   1..n-1. A hash of n or more is one hash in 2^32, and the wide product
//   happens to reduce it, so no test holds the reduction of the hash
//   either.
//
// Layered. The entries of the wide files the verifier calls are stubs:
// each asserts what it is handed, havocs what it writes, and the
// predicates answer an unconstrained value. The scalars' marshalling,
// their reduction and their two range predicates run on p256_scalar.c's
// real bodies, which the launch line links, so the range the proof states
// is the range the code tests.
//
// Not proven here: that the equation holds for a signature and for no
// other pair. bin/p256_verify_equiv_test holds the verdict to p256.c's
// 32-bit arm, and the host Wycheproof test to Wycheproof's.
#include "harness.h"

#include <string.h>

#include "p256_point.h"
#include "p256_scalar.h"
#include "p256_wide_point.h"
#include "p256_wide_scalar.h"
#include "p256_wide_verify_point.h"

// What the stubs saw: how many entries of the wide files ran, and what
// the predicates answered when they ran.
static unsigned wide_calls;
static int decoder_ran;
static uint32_t decoder_answer;
static int infinity_ran;
static int infinity_answer;
static int comparison_ran;
static int comparison_answer;

uint64_t nondet_u64(void);
int nondet_int(void);

static void scalar_havoc(p256_scalar *o) {
    for (size_t i = 0; i < P256_SCALAR_WORDS; i++) {
        o->word[i] = nondet_u32();
    }
}

static void point_havoc(p256_point *o) {
    for (size_t i = 0; i < P256_FE_WORDS; i++) {
        o->x.word[i] = nondet_u32();
        o->y.word[i] = nondet_u32();
        o->z.word[i] = nondet_u32();
    }
}

static void jacobian_havoc(p256_wide_jacobian *o) {
    for (size_t i = 0; i < P256_WIDE_FE_WORDS; i++) {
        o->x.word[i] = nondet_u64();
        o->y.word[i] = nondet_u64();
        o->z.word[i] = nondet_u64();
    }
}

static int below_n(const p256_scalar *a) {
    return p256_scalar_reduced_mask(a) == UINT32_MAX;
}

// p256_wide_scalar.h: both take scalars below n and leave one below n.
void p256_wide_scalar_inverse(p256_scalar *o, const p256_scalar *a) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a), "scalar inverse stub: operand readable");
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof *o), "scalar inverse stub: output writable");
    __CPROVER_assert(below_n(a), "scalar inverse stub: the operand is below n");
    wide_calls++;
    scalar_havoc(o);
    __CPROVER_assume(below_n(o));
}

void p256_wide_scalar_mul(p256_scalar *o, const p256_scalar *a, const p256_scalar *b) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a) && __CPROVER_r_ok(b, sizeof *b),
                     "scalar product stub: operands readable");
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof *o), "scalar product stub: output writable");
    __CPROVER_assert(below_n(a) && below_n(b), "scalar product stub: both operands are below n");
    wide_calls++;
    scalar_havoc(o);
    __CPROVER_assume(below_n(o));
}

// p256_wide_point.h: all ones for a point it took, and zero with nothing
// a caller may use in o.
uint32_t p256_wide_point_from_bytes(p256_point *o, const uint8_t in[P256_POINT_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(in, P256_POINT_LEN), "decoder stub: the encoding is readable");
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof *o), "decoder stub: output writable");
    __CPROVER_assert(in[0] == 0x04, "decoder stub: the encoding is the uncompressed one");
    wide_calls++;
    point_havoc(o);
    decoder_ran = 1;
    decoder_answer = nondet_mask();
    return decoder_answer;
}

// p256_wide_verify_point.h.
void p256_wide_jacobian_from_key(p256_wide_jacobian *o, const p256_point *key) {
    __CPROVER_assert(__CPROVER_r_ok(key, sizeof *key), "key stub: the key is readable");
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof *o), "key stub: output writable");
    __CPROVER_assert(decoder_ran && decoder_answer != 0, "key stub: the decoder took the key");
    wide_calls++;
    jacobian_havoc(o);
}

void p256_wide_jacobian_double_mul(p256_wide_jacobian *o, const p256_scalar *u1,
                                   const p256_scalar *u2, const p256_wide_jacobian *q) {
    __CPROVER_assert(__CPROVER_r_ok(u1, sizeof *u1) && __CPROVER_r_ok(u2, sizeof *u2) &&
                         __CPROVER_r_ok(q, sizeof *q),
                     "double multiplication stub: operands readable");
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof *o), "double multiplication stub: output writable");
    __CPROVER_assert(below_n(u1) && below_n(u2),
                     "double multiplication stub: both scalars are below n");
    wide_calls++;
    jacobian_havoc(o);
}

int p256_wide_jacobian_is_infinity(const p256_wide_jacobian *p) {
    __CPROVER_assert(__CPROVER_r_ok(p, sizeof *p), "infinity stub: the point is readable");
    wide_calls++;
    infinity_ran = 1;
    infinity_answer = nondet_int();
    __CPROVER_assume(infinity_answer == 0 || infinity_answer == 1);
    return infinity_answer;
}

int p256_wide_jacobian_x_is_r(const p256_wide_jacobian *sum, const p256_scalar *r) {
    __CPROVER_assert(__CPROVER_r_ok(sum, sizeof *sum) && __CPROVER_r_ok(r, sizeof *r),
                     "comparison stub: operands readable");
    __CPROVER_assert(infinity_ran && infinity_answer == 0,
                     "comparison stub: the sum was tested and is finite");
    __CPROVER_assert(below_n(r) && p256_scalar_zero_mask(r) == 0,
                     "comparison stub: r is in 1..n-1");
    wide_calls++;
    comparison_ran = 1;
    comparison_answer = nondet_int();
    __CPROVER_assume(comparison_answer == 0 || comparison_answer == 1);
    return comparison_answer;
}

#include "p256_wide_verify.c"

// 1 when the 32 big-endian bytes at bytes are a number in 1..n-1.
static int bytes_in_range(const uint8_t bytes[P256_SCALAR_LEN]) {
    p256_scalar value;
    p256_scalar_from_bytes(&value, bytes);
    return p256_scalar_zero_mask(&value) == 0 && p256_scalar_reduced_mask(&value) == UINT32_MAX;
}

int main(void) {
    uint8_t pub[64];
    uint8_t hash[32];
    uint8_t r_be[P256_SCALAR_LEN];
    uint8_t s_be[P256_SCALAR_LEN];
    fill_nondet(pub, sizeof pub);
    fill_nondet(hash, sizeof hash);
    fill_nondet(r_be, sizeof r_be);
    fill_nondet(s_be, sizeof s_be);
    int in_range = bytes_in_range(r_be) && bytes_in_range(s_be);

    wide_calls = 0;
    decoder_ran = 0;
    infinity_ran = 0;
    comparison_ran = 0;
    int verdict = p256_wide_verify_rs(pub, hash, r_be, s_be);

    __CPROVER_assert(verdict == 0 || verdict == 1, "verify: 0 or 1");
    if (!in_range) {
        __CPROVER_assert(verdict == 0, "verify: r or s outside 1..n-1 is no signature");
        __CPROVER_assert(wide_calls == 0, "verify: no wide entry runs for such a pair");
    }
    if (decoder_ran && decoder_answer == 0) {
        __CPROVER_assert(verdict == 0, "verify: a key the decoder refuses verifies nothing");
    }
    if (infinity_ran && infinity_answer == 1) {
        __CPROVER_assert(verdict == 0, "verify: a sum at infinity verifies nothing");
    }
    if (verdict == 1) {
        __CPROVER_assert(in_range && decoder_ran && infinity_ran && infinity_answer == 0 &&
                             comparison_ran && comparison_answer == 1,
                         "verify: 1 only after both range checks, the decoder, a finite sum and "
                         "a comparison that matched");
    }
    return 0;
}
