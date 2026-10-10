// The contracts the rsa_ifma_sign harnesses put in place of the three
// rsa_mont64.c entries rsa_ifma_sign.c calls, the way
// proof/rsa_sign64_stubs.h replaces that file's entries for rsa_sign64.c.
// A harness includes this header after proof/rsa_ifma_stubs.h and before
// rsa_ifma_sign.c, so the #defines below rename the calls in
// rsa_ifma_sign.c alone.
//
// Why this exists: state_setup multiplies once and doubles R mod m and
// the base spare times each, up to 48 doublings of 24 words at the
// 384-byte bound. With rsa_mont64.c's own text under those calls the
// setup harness passed 8 GB in two minutes, and the whole
// exponentiation's took six minutes and 5 GB at the 384-byte bound.
//
// WHAT EACH STUB MODELS: the entry's reads and writes and nothing of its
// values. Each asserts what the real entry needs of its arguments, so a
// call that breaks one fails here, and writes any words where the real
// entry writes.
//
//   - stub_sign_mont_mul and stub_sign_add need a modulus record whose
//     word count is 1 to RSA_MONT64_WORDS_MAX and that many readable
//     words behind each operand, and write that many words of the output.
//   - stub_sign_reduce_once_with_top needs the same of its one operand.
//
// WHAT DISCHARGES THE CONTRACTS: rsa_mont64_mul_harness.c proves the real
// multiplication with its output apart from both operands, the shape
// state_setup calls it in. rsa_mont64_ops_harness.c proves the real sum
// with its output and both operands one array, the shape of state_setup's
// doublings, and reduce_once, which rsa_mont64_reduce_once_with_top calls
// with its arguments unchanged, over any top word and with its output
// apart from its input, the shape state_finish calls it in.
//
// What the contracts give up: the values. bin/rsa_ifma_sign_model_test
// holds every exponentiation to rsa_sign64.c's window, and
// spec/lean/Spec/RsaIfma.lean's signPower_eq states what the
// exponentiation computes.
#ifndef CH_RSA_IFMA_SIGN_STUBS_H
#define CH_RSA_IFMA_SIGN_STUBS_H

#include "harness.h"

#include "rsa_mont64.h"

uint64_t nondet_u64(void);

static void stub_sign_mont_mul(uint64_t *o, const uint64_t *a, const uint64_t *b,
                               const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    __CPROVER_assert(k >= 1 && k <= RSA_MONT64_WORDS_MAX,
                     "rsa_mont64_mont_mul: a word count the record admits");
    __CPROVER_assert(__CPROVER_r_ok(a, k * sizeof(uint64_t)) &&
                         __CPROVER_r_ok(b, k * sizeof(uint64_t)),
                     "rsa_mont64_mont_mul: each operand holds the record's words");
    __CPROVER_assert(__CPROVER_w_ok(o, k * sizeof(uint64_t)),
                     "rsa_mont64_mont_mul: the output holds the record's words");
    for (size_t i = 0; i < k; i++) {
        o[i] = nondet_u64();
    }
}

static void stub_sign_add(uint64_t *o, const uint64_t *a, const uint64_t *b,
                          const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    __CPROVER_assert(k >= 1 && k <= RSA_MONT64_WORDS_MAX,
                     "rsa_mont64_add: a word count the record admits");
    __CPROVER_assert(__CPROVER_r_ok(a, k * sizeof(uint64_t)) &&
                         __CPROVER_r_ok(b, k * sizeof(uint64_t)),
                     "rsa_mont64_add: each operand holds the record's words");
    __CPROVER_assert(__CPROVER_w_ok(o, k * sizeof(uint64_t)),
                     "rsa_mont64_add: the output holds the record's words");
    for (size_t i = 0; i < k; i++) {
        o[i] = nondet_u64();
    }
}

static void stub_sign_reduce_once_with_top(uint64_t *o, const uint64_t *a, uint64_t top,
                                           const rsa_mont64_modulus *mod) {
    size_t k = mod->words;
    (void)top;
    __CPROVER_assert(k >= 1 && k <= RSA_MONT64_WORDS_MAX,
                     "rsa_mont64_reduce_once_with_top: a word count the record admits");
    __CPROVER_assert(__CPROVER_r_ok(a, k * sizeof(uint64_t)),
                     "rsa_mont64_reduce_once_with_top: the operand holds the record's words");
    __CPROVER_assert(__CPROVER_w_ok(o, k * sizeof(uint64_t)),
                     "rsa_mont64_reduce_once_with_top: the output holds the record's words");
    for (size_t i = 0; i < k; i++) {
        o[i] = nondet_u64();
    }
}

// From here on rsa_ifma_sign.c's calls into rsa_mont64.c are the contracts
// above.
#define rsa_mont64_mont_mul stub_sign_mont_mul
#define rsa_mont64_add stub_sign_add
#define rsa_mont64_reduce_once_with_top stub_sign_reduce_once_with_top

#endif
