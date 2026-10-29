// Proves: x25519_adx(), the clamp, x25519_adx_ladder() and adx_invert() of
// x25519_adx.c, are memory-safe and free of UB on any scalar and any point,
// with the five operations replaced by the stubs below.
//
// Each stub requires that its operands can be read and its output written,
// then writes any four words to the output. The operations are total: every
// four words are an element, and proof/x25519_adx_ops_harness.c and
// proof/x25519_adx_mul_harness.c prove them on any words. So the ladder needs
// no bound on the words a stub writes, and any words cover every value the
// real operations can write. What this harness adds is the C around them:
// the 255 reads of the scalar's bits, the swaps, the 254 squares and 11
// products of the inversion, the final reduction and each wipe.
#include "harness.h"

// The guard of test/x25519_adx_model.h, so x25519_adx.c's include of the
// model under CH_X25519_ADX_MODEL reads nothing, and the stubs stand in.
#define CH_TEST_X25519_ADX_MODEL_H 1

#include <stdint.h>

uint64_t nondet_u64(void);

#define ELEMENT_LEN (4 * sizeof(uint64_t))

static void stub_write(uint64_t o[4]) {
    __CPROVER_assert(__CPROVER_w_ok(o, ELEMENT_LEN), "an operation writes four words");
    for (int i = 0; i < 4; i++) {
        o[i] = nondet_u64();
    }
}

static void adx_mul(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]) {
    __CPROVER_assert(__CPROVER_r_ok(a, ELEMENT_LEN) && __CPROVER_r_ok(b, ELEMENT_LEN),
                     "mul reads four words of each operand");
    stub_write(o);
}

static void adx_sqr(uint64_t o[4], const uint64_t a[4]) {
    __CPROVER_assert(__CPROVER_r_ok(a, ELEMENT_LEN), "sqr reads four words");
    stub_write(o);
}

static void adx_add(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]) {
    __CPROVER_assert(__CPROVER_r_ok(a, ELEMENT_LEN) && __CPROVER_r_ok(b, ELEMENT_LEN),
                     "add reads four words of each operand");
    stub_write(o);
}

static void adx_sub(uint64_t o[4], const uint64_t a[4], const uint64_t b[4]) {
    __CPROVER_assert(__CPROVER_r_ok(a, ELEMENT_LEN) && __CPROVER_r_ok(b, ELEMENT_LEN),
                     "sub reads four words of each operand");
    stub_write(o);
}

static void adx_mul_a24(uint64_t o[4], const uint64_t a[4]) {
    __CPROVER_assert(__CPROVER_r_ok(a, ELEMENT_LEN), "mul_a24 reads four words");
    stub_write(o);
}

#include "x25519_adx.c"

int main(void) {
    uint8_t scalar[X25519_LEN];
    uint8_t point[X25519_LEN];
    uint8_t out[X25519_LEN];
    fill_nondet(scalar, sizeof scalar);
    fill_nondet(point, sizeof point);
    (void)x25519_adx(out, scalar, point);
    return 0;
}
