// Proves: x25519_adx.c's linear operations and its final reduction, over
// test/x25519_adx_model.h, are memory-safe, free of UB and wrap no unsigned
// value (--unsigned-overflow-check on the launch line), on any four words:
//
//   add      both operands any words. The last add of 38 times the carry to
//            word 0 carries out of no word.
//   sub      both operands any words. No word's difference wraps, and the
//            last subtraction of 38 times the borrow from word 0 borrows
//            from no word.
//   mul_a24  any words. As add.
//   reduce   the second half of a product, model_reduce, on any eight
//            words: the sum of the low half and 38 times the high half, and
//            then the fold of its carry. As add.
//   final    adx_reduce on any words writes a value below p.
//   cswap    either bit, any words: the two elements are swapped exactly
//            when the bit is 1.
//
// Each operation also runs in the aliasing shapes adx_step calls it in: the
// output on the first operand and the output on the second. The model
// copies its result to the output after it reads both operands, so these
// shapes write nothing early. That the words are the right value mod p is
// spec/lean/Spec/X25519Adx.lean's, which bin/diff_x25519_adx holds the
// model to. That the assembly writes the model's words is
// bin/x25519_adx_equiv_test's (docs/decisions.md 165).
#include "harness.h"

#include "x25519_adx.c"
// x25519_adx.c read the model under -DCH_X25519_ADX_MODEL, so its guard makes
// this line read nothing. It names the model by its path, which is how
// tools/impact_read.py learns that this harness compiles it.
#include "test/x25519_adx_model.h"

uint64_t nondet_u64(void);

static void havoc(fe f) {
    for (size_t i = 0; i < 4; i++) {
        f[i] = nondet_u64();
    }
}

// The 32 bytes the words hold are below p = 2^255 - 19: bit 255 is clear,
// and the value is not one of p..2^255 - 1, whose words are
// 0xffffffffffffffed..ff, then two words of all ones, then
// 0x7fffffffffffffff.
static void assert_canonical(const fe a) {
    __CPROVER_assert(a[3] <= UINT64_C(0x7fffffffffffffff), "reduce clears bit 255");
    __CPROVER_assert(!(a[3] == UINT64_C(0x7fffffffffffffff) && a[2] == UINT64_MAX &&
                       a[1] == UINT64_MAX && a[0] >= UINT64_C(0xffffffffffffffed)),
                     "reduce writes a value below p");
}

int main(void) {
    fe a;
    fe b;
    fe o;

    havoc(a);
    havoc(b);
    adx_add(o, a, b);
    havoc(a);
    havoc(b);
    adx_add(a, a, b);
    havoc(a);
    havoc(b);
    adx_add(b, a, b);

    havoc(a);
    havoc(b);
    adx_sub(o, a, b);
    havoc(a);
    havoc(b);
    adx_sub(a, a, b);
    havoc(a);
    havoc(b);
    adx_sub(b, a, b);

    havoc(a);
    adx_mul_a24(o, a);

    uint64_t t[8];
    for (size_t i = 0; i < 8; i++) {
        t[i] = nondet_u64();
    }
    model_reduce(o, t);

    havoc(a);
    adx_reduce(a);
    assert_canonical(a);

    fe p0;
    fe q0;
    havoc(a);
    havoc(b);
    for (size_t i = 0; i < 4; i++) {
        p0[i] = a[i];
        q0[i] = b[i];
    }
    uint64_t bit = nondet_u64();
    __CPROVER_assume(bit == 0 || bit == 1);
    adx_cswap(a, b, bit);
    for (size_t i = 0; i < 4; i++) {
        __CPROVER_assert(a[i] == (bit ? q0[i] : p0[i]) && b[i] == (bit ? p0[i] : q0[i]),
                         "cswap swaps exactly when the bit is 1");
    }
    return 0;
}
