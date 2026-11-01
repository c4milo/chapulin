// Proves, for the reduction of test/p256_adx_model.h, the model of the
// reduction both statements of p256_adx_asm.h end with:
//
//   memory safety and no unsigned wrap (--unsigned-overflow-check on the
//   launch line) over any eight words, through the four rounds and the
//   final subtraction;
//
//   that each round's carry out is 0 or 1 when the carry it is handed is,
//   so the high word of u times p's top word plus that carry fits a word
//   and model_reduce_once's top is a bit;
//
//   that the final subtraction writes the words p256_wide_field.c's
//   p256_wide_fe_reduce_once writes, on any four words and any carry of 0
//   or 1: the same choice by the same borrow.
//
// Not proven here: that a round writes the words reduce_round writes. The
// model multiplies u by p's top word, as MULX does, and reduce_round adds
// shifted copies of u. A formula holding both, one round of each, ran for
// 20 minutes under kissat on an M1 Pro with no verdict, and one holding the
// whole of both reductions for 16. What the rounds compute rests on
// spec/lean/Spec/P256Adx.lean's reduce_lt and reduce_mod, which
// bin/diff_p256_adx holds the C to, and on bin/p256_adx_model_test.
#include "harness.h"

#include "p256_wide_reference.h"

#define P256_WIDE_CARRY P256_WIDE_CARRY_BUILTIN
#include "p256_wide_field.c"
// The model by its path, which is how tools/impact_read.py learns that
// this harness compiles it.
#include "test/p256_adx_model.h"

// The four rounds and the final subtraction on any eight words.
static void prove_reduce(void) {
    uint64_t t[8];
    uint64_t o[P256_WIDE_FE_WORDS];
    for (size_t i = 0; i < 8; i++) {
        t[i] = nondet_u64();
    }
    uint64_t top = 0;
    for (int k = 0; k < 4; k++) {
        top = model_round(t, k, top);
        __CPROVER_assert(top <= 1, "model_round: the carry it returns is 0 or 1");
    }
    model_reduce_once(o, t, top);
}

// The final subtraction: model_reduce_once on words 4 to 7 against
// p256_wide_fe_reduce_once on the same words and carry.
static void prove_reduce_once(void) {
    uint64_t t[8];
    for (size_t i = 0; i < 8; i++) {
        t[i] = nondet_u64();
    }
    uint64_t top = nondet_u64();
    __CPROVER_assume(top <= 1);
    uint64_t want[P256_WIDE_FE_WORDS];
    uint64_t got[P256_WIDE_FE_WORDS];
    p256_wide_fe_reduce_once(want, t[4], t[5], t[6], t[7], top);
    model_reduce_once(got, t, top);
    __CPROVER_assert(words_same(got, want), "model_reduce_once: p256_wide_fe_reduce_once's words");
}

int main(void) {
    prove_reduce();
    prove_reduce_once();
    return 0;
}
