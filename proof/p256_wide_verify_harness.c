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
//   that it answers 0 for a key the decoder refuses, and for an R at
//   infinity, which the affine conversion reports. No test can hold
//   either: with the check gone, the arithmetic after it runs on limbs
//   that are no point, and its X matches r one time in 2^256;
//
//   that it answers 1 only after the decoder took the key and the
//   conversion gave an X;
//
//   that the bytes it hands the decoder start with 0x04, the leading byte
//   of the one encoding the decoder reads;
//
//   that every scalar it hands p256_wide_scalar_inverse and
//   p256_wide_scalar_mul is below n, which is what their contract takes.
//   A hash of n or more is one hash in 2^32, and the wide product
//   happens to reduce it, so no test holds the reduction of the hash
//   either.
//
// Layered. The nine entries of the wide files that the verifier calls are
// stubs: each asserts what it is handed, havocs what it writes, and the
// two predicates answer an unconstrained mask. The scalars' marshalling,
// their reduction and their two range predicates run on p256_scalar.c's
// real bodies, which the launch line links, so the range the proof
// states is the range the code tests.
//
// Not proven here: that the equation holds for a signature and for no
// other pair. bin/p256_verify_equiv_test holds the verdict to p256.c's
// 32-bit arm, and the Wycheproof host leg to Wycheproof's.
#include "harness.h"

#include <string.h>

#include "p256_point.h"
#include "p256_scalar.h"
#include "p256_wide_mul.h"
#include "p256_wide_point.h"
#include "p256_wide_scalar.h"

// What the stubs saw: how many entries of the wide files ran, and what
// the two predicates answered when they ran.
static unsigned wide_calls;
static int decoder_ran;
static uint32_t decoder_answer;
static int affine_ran;
static uint32_t affine_answer;

static void scalar_havoc(p256_scalar *o) {
    for (size_t i = 0; i < P256_SCALAR_LIMBS; i++) {
        o->limb[i] = nondet_u32();
    }
}

static void point_havoc(p256_point *o) {
    for (size_t i = 0; i < P256_FE_LIMBS; i++) {
        o->x.limb[i] = nondet_u32();
        o->y.limb[i] = nondet_u32();
        o->z.limb[i] = nondet_u32();
    }
}

uint64_t nondet_u64(void);

static void wide_point_havoc(p256_wide_point *o) {
    for (size_t i = 0; i < P256_WIDE_FE_LIMBS; i++) {
        o->x.limb[i] = nondet_u64();
        o->y.limb[i] = nondet_u64();
        o->z.limb[i] = nondet_u64();
    }
}

// p256_wide_scalar.h: both take scalars below n and leave one below n.
void p256_wide_scalar_inverse(p256_scalar *o, const p256_scalar *a) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a), "scalar inverse stub: operand readable");
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof *o), "scalar inverse stub: output writable");
    __CPROVER_assert(p256_scalar_reduced_mask(a) == UINT32_MAX,
                     "scalar inverse stub: the operand is below n");
    wide_calls++;
    scalar_havoc(o);
    __CPROVER_assume(p256_scalar_reduced_mask(o) == UINT32_MAX);
}

void p256_wide_scalar_mul(p256_scalar *o, const p256_scalar *a, const p256_scalar *b) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a) && __CPROVER_r_ok(b, sizeof *b),
                     "scalar product stub: operands readable");
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof *o), "scalar product stub: output writable");
    __CPROVER_assert(p256_scalar_reduced_mask(a) == UINT32_MAX &&
                         p256_scalar_reduced_mask(b) == UINT32_MAX,
                     "scalar product stub: both operands are below n");
    wide_calls++;
    scalar_havoc(o);
    __CPROVER_assume(p256_scalar_reduced_mask(o) == UINT32_MAX);
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

// p256_wide_mul.h: any scalar, reduced or not, and any point.
void p256_wide_base_mul(p256_point *o, const p256_scalar *k) {
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k), "base multiplication stub: scalar readable");
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof *o), "base multiplication stub: output writable");
    wide_calls++;
    point_havoc(o);
}

void p256_wide_mul(p256_point *o, const p256_scalar *k, const p256_point *p) {
    __CPROVER_assert(__CPROVER_r_ok(k, sizeof *k) && __CPROVER_r_ok(p, sizeof *p),
                     "multiplication stub: operands readable");
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof *o), "multiplication stub: output writable");
    wide_calls++;
    point_havoc(o);
}

void p256_wide_point_from_portable(p256_wide_point *o, const p256_point *a) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a), "conversion stub: point readable");
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof *o), "conversion stub: output writable");
    wide_calls++;
    wide_point_havoc(o);
}

void p256_wide_point_to_portable(p256_point *o, const p256_wide_point *a) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a), "conversion stub: point readable");
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof *o), "conversion stub: output writable");
    wide_calls++;
    point_havoc(o);
}

void p256_wide_point_add(p256_wide_point *o, const p256_wide_point *a, const p256_wide_point *b) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a) && __CPROVER_r_ok(b, sizeof *b),
                     "addition stub: operands readable");
    __CPROVER_assert(__CPROVER_w_ok(o, sizeof *o), "addition stub: output writable");
    wide_calls++;
    wide_point_havoc(o);
}

// p256_wide_point.h: writes X, and Y when y is not NULL, whatever the
// point is, and answers all ones for a finite point.
uint32_t p256_wide_point_affine(uint8_t x[P256_FE_LEN], uint8_t y[P256_FE_LEN],
                                const p256_point *a) {
    __CPROVER_assert(__CPROVER_r_ok(a, sizeof *a), "affine stub: point readable");
    __CPROVER_assert(__CPROVER_w_ok(x, P256_FE_LEN), "affine stub: X writable");
    __CPROVER_assert(y == NULL || __CPROVER_w_ok(y, P256_FE_LEN), "affine stub: Y writable");
    wide_calls++;
    fill_nondet(x, P256_FE_LEN);
    if (y != NULL) {
        fill_nondet(y, P256_FE_LEN);
    }
    affine_ran = 1;
    affine_answer = nondet_mask();
    return affine_answer;
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
    affine_ran = 0;
    int verdict = p256_wide_verify_rs(pub, hash, r_be, s_be);

    __CPROVER_assert(verdict == 0 || verdict == 1, "verify: 0 or 1");
    if (!in_range) {
        __CPROVER_assert(verdict == 0, "verify: r or s outside 1..n-1 is no signature");
        __CPROVER_assert(wide_calls == 0, "verify: no wide entry runs for such a pair");
    }
    if (decoder_ran && decoder_answer == 0) {
        __CPROVER_assert(verdict == 0, "verify: a key the decoder refuses verifies nothing");
    }
    if (affine_ran && affine_answer == 0) {
        __CPROVER_assert(verdict == 0, "verify: R at infinity verifies nothing");
    }
    if (verdict == 1) {
        __CPROVER_assert(in_range && decoder_ran && affine_ran,
                         "verify: 1 only after both range checks, the decoder and the conversion");
    }
    return 0;
}
