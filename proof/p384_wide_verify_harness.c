// Proves, for p384_wide_verify.c, the whole of p384_wide_verify_rs over
// an unconstrained key, hash, r and s:
//
//   memory safety and absence of UB;
//
//   that it answers 0 or 1;
//
//   that it answers 0 for an r or an s outside 1..n-1, and calls no entry
//   of the point file and no product for one. No test can hold the zero
//   half: with it gone, an s of zero has an inverse of zero, both scalars
//   are zero, and the sum is the point at infinity, which is refused
//   anyway;
//
//   that it answers 0 for a key the decoder refuses and for a sum at
//   infinity, and compares x with r only for a sum the infinity test
//   passed;
//
//   that it answers 1 only after the decoder took the key, the sum was
//   not infinity and the comparison said so;
//
//   that every scalar it hands p384_wide_mod_inverse and
//   p384_wide_mod_mul is below n, and the one it inverts is not zero,
//   which is what their contract takes. A hash of n or more is one hash
//   in 2^190, and the Montgomery product happens to reduce it, so no test
//   holds the reduction of the hash either.
//
// Layered. The four entries of p384_wide_point.c and the two routines of
// p384_wide_field.c that multiply are stubs: each asserts what it is
// handed and havocs what it writes, and the three predicates answer an
// unconstrained 0 or 1. The byte reader, the range predicates and the
// subtraction that reduces the hash run on p384_wide_field.c's real
// bodies, so the range the proof states is the range the code tests.
// proof/p384_wide_point_harness.c and proof/p384_wide_field_harness.c run
// what the stubs stand for.
//
// Not proven here: that the equation holds for a signature and for no
// other pair. bin/p384_equiv_test holds the verdict to p384.c's 32-bit
// arm, and the host Wycheproof test to Wycheproof's.
#include "harness.h"

#include <string.h>

// The field's real bodies under other names for the two routines the
// contracts below replace, and under their own for the rest.
#define p384_wide_mod_mul real_mod_mul
#define p384_wide_mod_inverse real_mod_inverse
#include "p384_wide_field.c"
#undef p384_wide_mod_mul
#undef p384_wide_mod_inverse

#include "p384_wide_point.h"

uint64_t nondet_u64(void);
int nondet_int(void);

// What the stubs saw: how many of them ran, and what the three
// predicates answered when they ran.
static unsigned stub_calls;
static int decoder_ran;
static int decoder_answer;
static int sum_written;
static int infinity_ran;
static int infinity_answer;
static int compare_ran;
static int compare_answer;

static int nondet_bit(void) {
    return nondet_int() != 0;
}

static int below_n(const uint64_t a[P384_WIDE_LIMBS]) {
    return p384_wide_compare(a, p384_wide_modn.m) < 0;
}

static void havoc_below_n(uint64_t o[P384_WIDE_LIMBS]) {
    for (size_t i = 0; i < P384_WIDE_LIMBS; i++) {
        o[i] = nondet_u64();
    }
    __CPROVER_assume(below_n(o));
}

static void havoc_point(p384_wide_point *o) {
    for (size_t i = 0; i < P384_WIDE_LIMBS; i++) {
        o->x[i] = nondet_u64();
        o->y[i] = nondet_u64();
        o->z[i] = nondet_u64();
    }
}

// p384_wide_field.h: inputs below mod->m, results below mod->m.
void p384_wide_mod_mul(uint64_t o[P384_WIDE_LIMBS], const uint64_t a[P384_WIDE_LIMBS],
                       const uint64_t b[P384_WIDE_LIMBS], const p384_wide_modulus *mod) {
    __CPROVER_assert(mod == &p384_wide_modn, "product stub: the verifier multiplies modulo n");
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof(uint64_t) * P384_WIDE_LIMBS),
                     "product stub: output writable");
    __CPROVER_assert(below_n(a) && below_n(b), "product stub: both operands are below n");
    stub_calls++;
    havoc_below_n(o);
}

// p384_wide_field.h: a must be non-zero.
void p384_wide_mod_inverse(uint64_t o[P384_WIDE_LIMBS], const uint64_t a[P384_WIDE_LIMBS],
                           const p384_wide_modulus *mod) {
    __CPROVER_assert(mod == &p384_wide_modn, "inverse stub: the verifier inverts modulo n");
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof(uint64_t) * P384_WIDE_LIMBS),
                     "inverse stub: output writable");
    __CPROVER_assert(below_n(a) && !p384_wide_is_zero(a), "inverse stub: the operand is in 1..n-1");
    stub_calls++;
    havoc_below_n(o);
}

// p384_wide_point.h: 1 for a key it took, and 0 with no point in q.
int p384_wide_point_decode(p384_wide_point *q, const uint8_t pub[P384_PUB_LEN]) {
    __CPROVER_assert(__CPROVER_r_ok(pub, P384_PUB_LEN), "decoder stub: the key is readable");
    __CPROVER_assert(__CPROVER_w_ok(q, sizeof *q), "decoder stub: output writable");
    stub_calls++;
    havoc_point(q);
    decoder_ran = 1;
    decoder_answer = nondet_bit();
    return decoder_answer;
}

// p384_wide_point.h: a q the decoder wrote, and scalars below n.
void p384_wide_double_mul(p384_wide_point *o, const uint64_t u1[P384_WIDE_LIMBS],
                          const uint64_t u2[P384_WIDE_LIMBS], const p384_wide_point *q) {
    __CPROVER_assert(__CPROVER_r_ok(q, sizeof *q), "sum stub: the key is readable");
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof *o), "sum stub: output writable");
    __CPROVER_assert(decoder_ran && decoder_answer == 1, "sum stub: the decoder took the key");
    __CPROVER_assert(below_n(u1) && below_n(u2), "sum stub: both scalars are below n");
    stub_calls++;
    havoc_point(o);
    sum_written = 1;
}

int p384_wide_point_is_infinity(const p384_wide_point *p) {
    __CPROVER_assert(__CPROVER_r_ok(p, sizeof *p), "infinity stub: point readable");
    __CPROVER_assert(sum_written, "infinity stub: the point is the sum");
    stub_calls++;
    infinity_ran = 1;
    infinity_answer = nondet_bit();
    return infinity_answer;
}

// p384_wide_point.h: a sum that is not infinity, and r in 1..n-1.
int p384_wide_point_x_is_r(const p384_wide_point *sum, const uint64_t r[P384_WIDE_LIMBS]) {
    __CPROVER_assert(__CPROVER_r_ok(sum, sizeof *sum), "comparison stub: point readable");
    __CPROVER_assert(infinity_ran && infinity_answer == 0,
                     "comparison stub: the sum is known not to be infinity");
    __CPROVER_assert(below_n(r) && !p384_wide_is_zero(r), "comparison stub: r is in 1..n-1");
    stub_calls++;
    compare_ran = 1;
    compare_answer = nondet_bit();
    return compare_answer;
}

#include "p384_wide_verify.c"

// 1 when the 48 big-endian bytes at bytes are a number in 1..n-1.
static int bytes_in_range(const uint8_t bytes[P384_LEN]) {
    uint64_t value[P384_WIDE_LIMBS];
    p384_wide_from_bytes(value, bytes);
    return !p384_wide_is_zero(value) && below_n(value);
}

int main(void) {
    uint8_t pub[P384_PUB_LEN];
    uint8_t hash[P384_LEN];
    uint8_t r_be[P384_LEN];
    uint8_t s_be[P384_LEN];
    fill_nondet(pub, sizeof pub);
    fill_nondet(hash, sizeof hash);
    fill_nondet(r_be, sizeof r_be);
    fill_nondet(s_be, sizeof s_be);
    int in_range = bytes_in_range(r_be) && bytes_in_range(s_be);

    stub_calls = 0;
    decoder_ran = 0;
    sum_written = 0;
    infinity_ran = 0;
    compare_ran = 0;
    int verdict = p384_wide_verify_rs(pub, hash, r_be, s_be);

    __CPROVER_assert(verdict == 0 || verdict == 1, "verify: 0 or 1");
    if (!in_range) {
        __CPROVER_assert(verdict == 0, "verify: r or s outside 1..n-1 is no signature");
        __CPROVER_assert(stub_calls == 0,
                         "verify: no point entry and no product runs for such a pair");
    }
    if (decoder_ran && decoder_answer == 0) {
        __CPROVER_assert(verdict == 0, "verify: a key the decoder refuses verifies nothing");
    }
    if (infinity_ran && infinity_answer == 1) {
        __CPROVER_assert(verdict == 0, "verify: a sum at infinity verifies nothing");
    }
    if (verdict == 1) {
        __CPROVER_assert(in_range && decoder_ran && compare_ran && compare_answer == 1,
                         "verify: 1 only after both range checks, the decoder and the comparison");
    }
    return 0;
}
